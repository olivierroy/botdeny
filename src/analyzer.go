package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Config tunable thresholds for suspicious detection.
type Config struct {
	MinRequests         int
	MaxAverageRPM       float64
	MaxBurstWindow      time.Duration
	MaxBurstRequests    int
	Min404Errors        int
	MinErrorRatio       float64
	MinUniquePaths      int
	ScoreThreshold      int
	WhitelistAgents     []string
	MinPHP404s          int
	SuspiciousCountries []string
	AllowedIPs          []string
	AllowedCIDRs        []string
}

// DefaultConfig provides baseline heuristics for suspicious traffic.
func DefaultConfig() Config {
	return Config{
		MinRequests:      50,
		MaxAverageRPM:    90,
		MaxBurstWindow:   time.Minute,
		MaxBurstRequests: 80,
		Min404Errors:     20,
		MinErrorRatio:    0.5,
		MinUniquePaths:   150,
		ScoreThreshold:   2,
		WhitelistAgents: []string{
			"Googlebot",
			"bingbot",
			"BingPreview",
			"Pinterestbot",
			"Baiduspider",
			"YandexBot",
			"DuckDuckBot",
			"Applebot",
			"Preload",
		},
		MinPHP404s:          10,
		SuspiciousCountries: []string{"CN", "RU", "KP", "IR"},
		AllowedIPs:          nil,
		AllowedCIDRs:        nil,
	}
}

// IPStats aggregates metrics per source IP.
type IPStats struct {
	IP           string
	Requests     int
	FirstSeen    time.Time
	LastSeen     time.Time
	StatusCounts map[int]int
	UniquePaths  map[string]struct{}
	UserAgents   map[string]int
	Bytes        int64
	BurstWindows []time.Time
	PathCounts   map[string]int
	Whitelisted  bool
	CountryISO   string
	CountryName  string
	PHP404s      int
}

// Analyzer encapsulates the detection logic state.
type Analyzer struct {
	cfg        Config
	stats      map[string]*IPStats
	geoLookup  GeoLookup
	allowIPs   map[string]struct{}
	allowCIDRs []*net.IPNet
}

// New returns a configured Analyzer.
func New(cfg Config, geo GeoLookup) *Analyzer {
	allowed := make(map[string]struct{})
	for _, ip := range cfg.AllowedIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		allowed[ip] = struct{}{}
	}

	cidrs := make([]*net.IPNet, 0, len(cfg.AllowedCIDRs))
	for _, raw := range cfg.AllowedCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			continue
		}
		cidrs = append(cidrs, network)
	}

	return &Analyzer{
		cfg:        cfg,
		stats:      make(map[string]*IPStats),
		geoLookup:  geo,
		allowIPs:   allowed,
		allowCIDRs: cidrs,
	}
}

// Process updates the analyzer with a new log entry.
func (a *Analyzer) Process(entry Entry) {
	ip := entry.ClientIP
	if ip == "" {
		ip = entry.RemoteAddr
	}

	ipStat, ok := a.stats[ip]
	if !ok {
		ipStat = &IPStats{
			IP:           ip,
			StatusCounts: make(map[int]int),
			UniquePaths:  make(map[string]struct{}),
			UserAgents:   make(map[string]int),
			PathCounts:   make(map[string]int),
		}
		if a.geoLookup != nil {
			if info, ok := a.geoLookup(ip); ok {
				ipStat.CountryISO = info.CountryISO
				ipStat.CountryName = info.CountryName
			}
		}
		a.stats[ip] = ipStat
	}

	ipStat.Requests++
	if ipStat.FirstSeen.IsZero() || entry.Time.Before(ipStat.FirstSeen) {
		ipStat.FirstSeen = entry.Time
	}
	if entry.Time.After(ipStat.LastSeen) {
		ipStat.LastSeen = entry.Time
	}

	ipStat.StatusCounts[entry.Status]++
	if len(ipStat.UniquePaths) <= 500 {
		if len(entry.URI) > 0 {
			ipStat.UniquePaths[entry.URI] = struct{}{}
		}
	}
	if len(ipStat.PathCounts) <= 500 {
		if len(entry.URI) > 0 {
			ipStat.PathCounts[entry.URI]++
		}
	}

	if entry.UserAgent != "" {
		ipStat.UserAgents[entry.UserAgent]++
		if containsSubstring(entry.UserAgent, a.cfg.WhitelistAgents) {
			ipStat.Whitelisted = true
		}
	}

	if entry.Status == 404 && strings.Contains(strings.ToLower(entry.URI), ".php") {
		ipStat.PHP404s++
	}

	ipStat.Bytes += entry.Bytes
	ipStat.BurstWindows = append(ipStat.BurstWindows, entry.Time)
}

// Suspicion represents an IP flagged as suspicious with supporting details.
type Suspicion struct {
	IP      string
	Score   int
	Reasons []string
	Stats   *IPStats
}

// Suspicious returns suspicious IPs sorted by score descending.
func (a *Analyzer) Suspicious() []Suspicion {
	suspects := make([]Suspicion, 0)

	for _, stat := range a.stats {
		if a.isAllowed(stat.IP) {
			continue
		}
		if stat.Whitelisted {
			continue
		}
		score := 0
		reasons := make([]string, 0)

		duration := stat.LastSeen.Sub(stat.FirstSeen)
		if duration < time.Minute {
			duration = time.Minute
		}
		avgRPM := float64(stat.Requests) / duration.Minutes()
		if stat.Requests >= a.cfg.MinRequests && avgRPM > a.cfg.MaxAverageRPM {
			score++
			reasons = append(reasons, fmt.Sprintf("avg rpm %.1f > %.1f", avgRPM, a.cfg.MaxAverageRPM))
		}

		if burst := maxBurst(stat.BurstWindows, a.cfg.MaxBurstWindow); burst > a.cfg.MaxBurstRequests {
			score++
			reasons = append(reasons, fmt.Sprintf("burst %d req in %s", burst, a.cfg.MaxBurstWindow))
		}

		errorCount := 0
		for status, count := range stat.StatusCounts {
			if status >= 400 {
				errorCount += count
			}
		}
		if errorCount >= a.cfg.Min404Errors {
			score++
			reasons = append(reasons, fmt.Sprintf("%d error responses", errorCount))
		}

		if stat.Requests > 0 {
			ratio := float64(errorCount) / float64(stat.Requests)
			if ratio >= a.cfg.MinErrorRatio {
				score++
				reasons = append(reasons, fmt.Sprintf("error ratio %.0f%%", ratio*100))
			}
		}

		if unique := len(stat.UniquePaths); unique >= a.cfg.MinUniquePaths {
			score++
			reasons = append(reasons, fmt.Sprintf("%d unique paths", unique))
		}

		if stat.PHP404s >= a.cfg.MinPHP404s {
			score++
			reasons = append(reasons, fmt.Sprintf("%d php 404s", stat.PHP404s))
		}

		if stat.CountryISO != "" && containsStringCI(stat.CountryISO, a.cfg.SuspiciousCountries) {
			score++
			reasons = append(reasons, fmt.Sprintf("country %s flagged", stat.CountryISO))
		}

		if score >= a.cfg.ScoreThreshold {
			suspects = append(suspects, Suspicion{
				IP:      stat.IP,
				Score:   score,
				Reasons: reasons,
				Stats:   stat,
			})
		}
	}

	sort.Slice(suspects, func(i, j int) bool {
		if suspects[i].Score == suspects[j].Score {
			return suspects[i].Stats.Requests > suspects[j].Stats.Requests
		}
		return suspects[i].Score > suspects[j].Score
	})

	return suspects
}

func maxBurst(times []time.Time, window time.Duration) int {
	if len(times) == 0 {
		return 0
	}

	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })

	maxCount := 0
	start := 0

	for end := 0; end < len(times); end++ {
		for times[end].Sub(times[start]) > window {
			start++
		}
		count := end - start + 1
		if count > maxCount {
			maxCount = count
		}
	}

	return maxCount
}

func (a *Analyzer) isAllowed(ip string) bool {
	if ip == "" {
		return false
	}
	if _, ok := a.allowIPs[ip]; ok {
		return true
	}
	if len(a.allowCIDRs) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range a.allowCIDRs {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func containsSubstring(value string, substrings []string) bool {
	for _, sub := range substrings {
		if sub == "" {
			continue
		}
		if strings.Contains(value, sub) {
			return true
		}
	}
	return false
}

func containsStringCI(value string, items []string) bool {
	for _, item := range items {
		if strings.EqualFold(value, item) {
			return true
		}
	}
	return false
}

// TopPaths returns the highest frequency paths for display purposes.
func TopPaths(stat *IPStats, limit int) []string {
	if len(stat.PathCounts) == 0 || limit <= 0 {
		return nil
	}

	type kv struct {
		path  string
		count int
	}

	items := make([]kv, 0, len(stat.PathCounts))
	for path, count := range stat.PathCounts {
		items = append(items, kv{path: path, count: count})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].path < items[j].path
		}
		return items[i].count > items[j].count
	})

	if len(items) > limit {
		items = items[:limit]
	}

	results := make([]string, len(items))
	for i, item := range items {
		results[i] = fmt.Sprintf("%dx %s", item.count, item.path)
	}

	return results
}
