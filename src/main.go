package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
)

func main() {
	configPath := detectConfigPath(os.Args[1:])
	var fileCfg FileConfig
	if configPath != "" {
		cfgFromFile, err := loadFileConfig(configPath)
		if err != nil {
			log.Fatalf("load config %s: %v", configPath, err)
		}
		fileCfg = cfgFromFile
	}

	cfg := DefaultConfig()
	if err := applyConfigDefaults(&cfg, fileCfg); err != nil {
		log.Fatalf("apply config defaults: %v", err)
	}

	defaults, err := defaultsFromFileConfig(fileCfg)
	if err != nil {
		log.Fatalf("config defaults: %v", err)
	}

	filePath := flag.String("file", defaults.File, "path to Nginx access log")
	topN := flag.Int("top", defaults.Top, "maximum suspicious IPs to print")
	colorize := flag.Bool("color", defaults.Color, "enable ANSI color output")
	geoDB := flag.String("geoip-db", defaults.GeoIPDB, "path to MaxMind GeoIP2/GeoLite2 Country database")
	denyOutput := flag.String("deny-output", defaults.DenyOutput, "path to write Nginx deny config (optional)")
	denyExpiry := flag.Duration("deny-expiry", defaults.DenyExpiry, "lifetime for deny entries used in expiration comments (e.g. 168h)")
	nginxReload := flag.Bool("nginx-reload", defaults.NginxReload, "after writing deny file run 'nginx -t' then 'nginx -s reload'")
	nginxBin := flag.String("nginx-bin", defaults.NginxBin, "path to nginx binary")
	blockLog := flag.String("block-log", defaults.BlockLog, "path to append block report log (optional)")
	configFlag := flag.String("config", configPath, "path to YAML config file")

	additionalWhitelist := make([]string, 0)
	penalizedCountries := make([]string, 0)
	allowIPsFromFlags := make([]string, 0)
	allowCIDRsFromFlags := make([]string, 0)
	allowIPFiles := append([]string{}, defaults.AllowIPFiles...)
	flag.IntVar(&cfg.MinRequests, "min-requests", cfg.MinRequests, "minimum requests before considering an IP")
	flag.Float64Var(&cfg.MaxAverageRPM, "max-rpm", cfg.MaxAverageRPM, "flag if average requests per minute exceeds this value")
	flag.IntVar(&cfg.MaxBurstRequests, "burst", cfg.MaxBurstRequests, "flag if number of requests within burst window exceeds this value")
	flag.DurationVar(&cfg.MaxBurstWindow, "burst-window", cfg.MaxBurstWindow, "time window for burst analysis")
	flag.IntVar(&cfg.Min404Errors, "min-errors", cfg.Min404Errors, "flag if number of error responses exceeds this value")
	flag.Float64Var(&cfg.MinErrorRatio, "error-ratio", cfg.MinErrorRatio, "flag if error ratio meets or exceeds this value")
	flag.IntVar(&cfg.MinUniquePaths, "unique-paths", cfg.MinUniquePaths, "flag if unique paths meets or exceeds this value")
	flag.IntVar(&cfg.MinPHP404s, "php404", cfg.MinPHP404s, "flag if number of 404 responses for .php URIs exceeds this value")
	flag.IntVar(&cfg.ScoreThreshold, "score-threshold", cfg.ScoreThreshold, "minimum score before an IP is reported")
	flag.Float64Var(&cfg.MaxErrorPercent, "max-error-percent", cfg.MaxErrorPercent, "do not block if overall error percentage is below this threshold")
	flag.Func("allow-agent", "user agent substring to treat as trusted (can repeat)", func(val string) error {
		if val != "" {
			additionalWhitelist = append(additionalWhitelist, val)
		}
		return nil
	})
	flag.Func("bot-country", "ISO country code to penalise as bot-heavy (can repeat)", func(val string) error {
		if val != "" {
			penalizedCountries = append(penalizedCountries, val)
		}
		return nil
	})
	flag.Func("allow-ip", "source IP to treat as allowed (can repeat)", func(val string) error {
		if val != "" {
			allowIPsFromFlags = append(allowIPsFromFlags, val)
		}
		return nil
	})
	flag.Func("allow-cidr", "CIDR range to treat as allowed (can repeat)", func(val string) error {
		if val != "" {
			allowCIDRsFromFlags = append(allowCIDRsFromFlags, val)
		}
		return nil
	})
	flag.Func("allow-ip-file", "path to file listing trusted proxy IPs/CIDRs (can repeat)", func(val string) error {
		if val != "" {
			allowIPFiles = append(allowIPFiles, val)
		}
		return nil
	})
	flag.Parse()

	if *configFlag != configPath && *configFlag != "" {
		cfgFromFile, err := loadFileConfig(*configFlag)
		if err != nil {
			log.Fatalf("load config %s: %v", *configFlag, err)
		}
		if err := applyConfigDefaults(&cfg, cfgFromFile); err != nil {
			log.Fatalf("apply config defaults: %v", err)
		}
		if len(cfgFromFile.AllowIPFiles) > 0 {
			allowIPFiles = append(allowIPFiles, cfgFromFile.AllowIPFiles...)
		}
	}

	if len(additionalWhitelist) > 0 {
		cfg.WhitelistAgents = dedupeStrings(append(cfg.WhitelistAgents, additionalWhitelist...))
	}
	if len(penalizedCountries) > 0 {
		cfg.SuspiciousCountries = dedupeStrings(append(cfg.SuspiciousCountries, penalizedCountries...))
	}
	if len(allowIPsFromFlags) > 0 {
		cfg.AllowedIPs = dedupeStrings(append(cfg.AllowedIPs, allowIPsFromFlags...))
	}
	if len(allowCIDRsFromFlags) > 0 {
		cfg.AllowedCIDRs = dedupeStrings(append(cfg.AllowedCIDRs, allowCIDRsFromFlags...))
	}

	if len(allowIPFiles) > 0 {
		ips, cidrs, err := loadAllowIPsFromFiles(allowIPFiles)
		if err != nil {
			log.Fatalf("load allow ip files: %v", err)
		}
		if len(ips) > 0 {
			cfg.AllowedIPs = dedupeStrings(append(cfg.AllowedIPs, ips...))
		}
		if len(cidrs) > 0 {
			cfg.AllowedCIDRs = dedupeStrings(append(cfg.AllowedCIDRs, cidrs...))
		}
	}

	var (
		geoLookup GeoLookup
		geoCloser func() error
	)
	if *geoDB != "" {
		var err error
		geoLookup, geoCloser, err = newGeoLookup(*geoDB)
		if err != nil {
			log.Fatalf("open geoip db: %v", err)
		}
		defer func() {
			if err := geoCloser(); err != nil {
				log.Printf("close geoip db: %v", err)
			}
		}()
	}

	fh, err := os.Open(*filePath)
	if err != nil {
		log.Fatalf("open log: %v", err)
	}
	defer fh.Close()

	analyzer := New(cfg, geoLookup)
	entries, errs := Stream(fh)

	for entry := range entries {
		analyzer.Process(entry)
	}

	if err := <-errs; err != nil {
		log.Fatalf("parse log: %v", err)
	}

	suspects := analyzer.Suspicious()
	if len(suspects) == 0 {
		fmt.Println("no suspicious IPs detected with current thresholds")
		return
	}
	totalRequests := 0
	totalErrors := 0
	for _, stat := range analyzer.Stats() {
		totalRequests += stat.Requests
		for status, count := range stat.StatusCounts {
			if status >= 400 {
				totalErrors += count
			}
		}
	}
	errorPercent := 0.0
	if totalRequests > 0 {
		errorPercent = (float64(totalErrors) / float64(totalRequests)) * 100
	}

	displaySuspects := suspects
	if *topN > 0 && len(displaySuspects) > *topN {
		displaySuspects = displaySuspects[:*topN]
	}

	header := fmt.Sprintf("%-16s %-8s %-6s %-12s %-12s %-8s %-8s %s", "IP", "Country", "Score", "Requests", "Errors", "First", "Last", "Reasons")
	fmt.Println(maybeColor(*colorize, ansiBold, header))
	fmt.Println(maybeColor(*colorize, ansiDim, strings.Repeat("-", len(header))))
	for _, suspect := range displaySuspects {
		errors := 0
		for status, count := range suspect.Stats.StatusCounts {
			if status >= 400 {
				errors += count
			}
		}

		country := "-"
		if suspect.Stats.CountryISO != "" {
			country = suspect.Stats.CountryISO
		} else if suspect.Stats.CountryName != "" {
			country = suspect.Stats.CountryName
		}

		line := fmt.Sprintf("%-16s %-8s %-6d %-12d %-12d %-8s %-8s %s",
			suspect.IP,
			country,
			suspect.Score,
			suspect.Stats.Requests,
			errors,
			suspect.Stats.FirstSeen.Format(time.Kitchen),
			suspect.Stats.LastSeen.Format(time.Kitchen),
			strings.Join(suspect.Reasons, "; "))
		fmt.Println(maybeColor(*colorize, colorForScore(suspect.Score), line))

		uaLine := fmt.Sprintf("    user-agents: %s", topUserAgents(suspect.Stats))
		fmt.Println(maybeColor(*colorize, ansiDim, uaLine))
		if suspect.Stats.CountryISO != "" || suspect.Stats.CountryName != "" {
			iso := suspect.Stats.CountryISO
			if iso == "" {
				iso = "-"
			}
			name := suspect.Stats.CountryName
			if name == "" {
				name = "-"
			}
			geoLine := fmt.Sprintf("    geo: %s (%s)", iso, name)
			fmt.Println(maybeColor(*colorize, ansiDim, geoLine))
		}
		if paths := TopPaths(suspect.Stats, 5); len(paths) > 0 {
			pathLine := fmt.Sprintf("    paths: %s", strings.Join(paths, "; "))
			fmt.Println(maybeColor(*colorize, ansiDim, pathLine))
		}
	}

	if *blockLog != "" {
		if err := appendBlockLog(*blockLog, suspects); err != nil {
			log.Printf("write block log: %v", err)
		}
	}

	if *denyOutput != "" {
		skipDeny := errorPercent > cfg.MaxErrorPercent
		if skipDeny {
			log.Printf("skip deny config: error rate %.2f%% exceeds max %.2f%%", errorPercent, cfg.MaxErrorPercent)
		} else {
			if err := writeDenyFile(*denyOutput, suspects, *denyExpiry); err != nil {
				log.Fatalf("write deny config: %v", err)
			}
			log.Printf("wrote deny config to %s (%d entries, error rate %.2f%%)", *denyOutput, len(suspects), errorPercent)

			if *nginxReload {
				if err := runNginxReload(*nginxBin); err != nil {
					log.Fatalf("nginx reload: %v", err)
				}
				log.Print("nginx reloaded successfully")
			}
		}
	}
}

func topUserAgents(stat *IPStats) string {
	if len(stat.UserAgents) == 0 {
		return "(none)"
	}

	type kv struct {
		ua    string
		count int
	}

	top := make([]kv, 0, len(stat.UserAgents))
	for ua, count := range stat.UserAgents {
		top = append(top, kv{ua: ua, count: count})
	}

	sort.Slice(top, func(i, j int) bool { return top[i].count > top[j].count })
	if len(top) > 3 {
		top = top[:3]
	}

	parts := make([]string, len(top))
	for i, item := range top {
		parts[i] = fmt.Sprintf("%dx %s", item.count, item.ua)
	}

	return strings.Join(parts, "; ")
}

func maybeColor(enabled bool, code, text string) string {
	if !enabled || code == "" {
		return text
	}
	return code + text + ansiReset
}

func colorForScore(score int) string {
	switch {
	case score >= 4:
		return ansiRed
	case score >= 3:
		return ansiYellow
	case score >= 2:
		return ansiGreen
	default:
		return ""
	}
}

func writeDenyFile(path string, suspects []Suspicion, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	now := time.Now().UTC()
	expiry := now.Add(ttl)

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("# generated by botdeny on %s UTC\n", now.Format(time.RFC3339)))
	if len(suspects) == 0 {
		builder.WriteString("# no suspicious IPs detected with current thresholds\n")
	} else {
		for _, suspect := range suspects {
			reasons := strings.Join(suspect.Reasons, "; ")
			reasons = strings.ReplaceAll(reasons, "\n", " ")
			errors := 0
			for status, count := range suspect.Stats.StatusCounts {
				if status >= 400 {
					errors += count
				}
			}
			iso := suspect.Stats.CountryISO
			if iso == "" {
				iso = "-"
			}
			name := suspect.Stats.CountryName
			if name == "" {
				name = "-"
			}
			comment := fmt.Sprintf("expires %s; errors=%d; country=%s (%s)", expiry.Format("2006-01-02"), errors, iso, name)
			if reasons != "" {
				comment = fmt.Sprintf("%s; %s", comment, reasons)
			}
			builder.WriteString(fmt.Sprintf("deny %s; # %s\n", suspect.IP, comment))
		}
	}

	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

func runNginxReload(binary string) error {
	if binary == "" {
		binary = "nginx"
	}

	testCmd := exec.Command(binary, "-t")
	var testOut bytes.Buffer
	testCmd.Stdout = &testOut
	testCmd.Stderr = &testOut
	if err := testCmd.Run(); err != nil {
		return fmt.Errorf("nginx -t failed: %w\n%s", err, testOut.String())
	}

	reloadCmd := exec.Command(binary, "-s", "reload")
	var reloadOut bytes.Buffer
	reloadCmd.Stdout = &reloadOut
	reloadCmd.Stderr = &reloadOut
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("nginx -s reload failed: %w\n%s", err, reloadOut.String())
	}

	if out := strings.TrimSpace(testOut.String()); out != "" {
		log.Printf("nginx -t output:\n%s", out)
	}
	if out := strings.TrimSpace(reloadOut.String()); out != "" {
		log.Printf("nginx reload output:\n%s", out)
	}

	return nil
}

func appendBlockLog(path string, suspects []Suspicion) error {
	if path == "" {
		return nil
	}

	now := time.Now().UTC()
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s total=%d\n", now.Format(time.RFC3339), len(suspects)))
	if len(suspects) == 0 {
		builder.WriteString("  none\n\n")
	} else {
		for _, suspect := range suspects {
			country := suspect.Stats.CountryISO
			if country == "" {
				country = suspect.Stats.CountryName
			}
			if country == "" {
				country = "-"
			}
			reasons := strings.Join(suspect.Reasons, "; ")
			reasons = strings.ReplaceAll(reasons, "\n", " ")
			builder.WriteString(fmt.Sprintf("  %s score=%d country=%s reasons=%s\n",
				suspect.IP,
				suspect.Score,
				country,
				reasons))
		}
		builder.WriteString("\n")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(builder.String()); err != nil {
		return err
	}

	return nil
}

func loadAllowIPsFromFiles(paths []string) ([]string, []string, error) {
	if len(paths) == 0 {
		return nil, nil, nil
	}

	ips := make([]string, 0)
	cidrs := make([]string, 0)

	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("open %s: %w", path, err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !strings.HasPrefix(line, "set_real_ip_from") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			value := fields[1]
			value = strings.TrimSuffix(value, ";")
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if strings.Contains(value, "/") {
				cidrs = append(cidrs, value)
			} else {
				ips = append(ips, value)
			}
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, nil, fmt.Errorf("scan %s: %w", path, err)
		}
		file.Close()
	}

	return ips, cidrs, nil
}
