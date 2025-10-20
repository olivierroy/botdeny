package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FileConfig represents configuration options supplied via YAML.
type FileConfig struct {
	File             string   `yaml:"file"`
	Top              *int     `yaml:"top"`
	Color            *bool    `yaml:"color"`
	GeoIPDB          string   `yaml:"geoip_db"`
	DenyOutput       string   `yaml:"deny_output"`
	DenyExpiry       string   `yaml:"deny_expiry"`
	NginxReload      *bool    `yaml:"nginx_reload"`
	NginxBin         string   `yaml:"nginx_bin"`
	BlockLog         string   `yaml:"block_log"`
	AllowAgents      []string `yaml:"allow_agents"`
	BotCountries     []string `yaml:"bot_countries"`
	AllowIPs         []string `yaml:"allow_ips"`
	AllowCIDRs       []string `yaml:"allow_cidrs"`
	AllowIPFiles     []string `yaml:"allow_ip_files"`
	AllowURLs        []string `yaml:"allow_urls"`
	MinRequests      *int     `yaml:"min_requests"`
	MaxAverageRPM    *float64 `yaml:"max_average_rpm"`
	MaxBurstWindow   string   `yaml:"max_burst_window"`
	MaxBurstRequests *int     `yaml:"max_burst_requests"`
	Min404Errors     *int     `yaml:"min_404_errors"`
	MinErrorRatio    *float64 `yaml:"min_error_ratio"`
	MinUniquePaths   *int     `yaml:"min_unique_paths"`
	ScoreThreshold   *int     `yaml:"score_threshold"`
	MinPHP404s       *int     `yaml:"min_php_404s"`
	MaxErrorPercent  *float64 `yaml:"max_error_percent"`
	MinSQLInjections *int     `yaml:"min_sql_injections"`
}

// RuntimeDefaults carries non-Config defaults sourced from YAML.
type RuntimeDefaults struct {
	File         string
	Top          int
	Color        bool
	GeoIPDB      string
	DenyOutput   string
	DenyExpiry   time.Duration
	NginxReload  bool
	NginxBin     string
	BlockLog     string
	AllowIPFiles []string
}

// detectConfigPath extracts the --config flag from arguments before flag.Parse.
func detectConfigPath(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config=")
		}
		if arg == "--config" || arg == "-config" {
			if i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return ""
}

func loadFileConfig(path string) (FileConfig, error) {
	var cfg FileConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyConfigDefaults(target *Config, fc FileConfig) error {
	if fc.MinRequests != nil {
		target.MinRequests = *fc.MinRequests
	}
	if fc.MaxAverageRPM != nil {
		target.MaxAverageRPM = *fc.MaxAverageRPM
	}
	if fc.MaxBurstWindow != "" {
		d, err := time.ParseDuration(fc.MaxBurstWindow)
		if err != nil {
			return fmt.Errorf("parse max_burst_window: %w", err)
		}
		target.MaxBurstWindow = d
	}
	if fc.MaxBurstRequests != nil {
		target.MaxBurstRequests = *fc.MaxBurstRequests
	}
	if fc.Min404Errors != nil {
		target.Min404Errors = *fc.Min404Errors
	}
	if fc.MinErrorRatio != nil {
		target.MinErrorRatio = *fc.MinErrorRatio
	}
	if fc.MinUniquePaths != nil {
		target.MinUniquePaths = *fc.MinUniquePaths
	}
	if fc.ScoreThreshold != nil {
		target.ScoreThreshold = *fc.ScoreThreshold
	}
	if fc.MinPHP404s != nil {
		target.MinPHP404s = *fc.MinPHP404s
	}
	if len(fc.AllowAgents) > 0 {
		target.WhitelistAgents = dedupeStrings(append(target.WhitelistAgents, fc.AllowAgents...))
	}
	if len(fc.BotCountries) > 0 {
		target.SuspiciousCountries = dedupeStrings(append(target.SuspiciousCountries, fc.BotCountries...))
	}
	if len(fc.AllowIPs) > 0 {
		target.AllowedIPs = dedupeStrings(append(target.AllowedIPs, fc.AllowIPs...))
	}
	if len(fc.AllowCIDRs) > 0 {
		target.AllowedCIDRs = dedupeStrings(append(target.AllowedCIDRs, fc.AllowCIDRs...))
	}
	if len(fc.AllowURLs) > 0 {
		target.AllowedURIs = dedupeStrings(append(target.AllowedURIs, fc.AllowURLs...))
	}
	if fc.MaxErrorPercent != nil {
		target.MaxErrorPercent = *fc.MaxErrorPercent
	}
	if fc.MinSQLInjections != nil {
		target.MinSQLInjections = *fc.MinSQLInjections
	}
	return nil
}

func defaultsFromFileConfig(fc FileConfig) (RuntimeDefaults, error) {
	defaults := RuntimeDefaults{
		File:         "access.log",
		Top:          10,
		Color:        false,
		GeoIPDB:      fc.GeoIPDB,
		DenyOutput:   fc.DenyOutput,
		DenyExpiry:   7 * 24 * time.Hour,
		NginxReload:  false,
		NginxBin:     "nginx",
		BlockLog:     fc.BlockLog,
		AllowIPFiles: append([]string{}, fc.AllowIPFiles...),
	}

	if fc.File != "" {
		defaults.File = fc.File
	}
	if fc.Top != nil {
		defaults.Top = *fc.Top
	}
	if fc.Color != nil {
		defaults.Color = *fc.Color
	}
	if fc.DenyExpiry != "" {
		d, err := time.ParseDuration(fc.DenyExpiry)
		if err != nil {
			return defaults, fmt.Errorf("parse deny_expiry: %w", err)
		}
		defaults.DenyExpiry = d
	}
	if fc.NginxReload != nil {
		defaults.NginxReload = *fc.NginxReload
	}
	if fc.NginxBin != "" {
		defaults.NginxBin = fc.NginxBin
	}
	if fc.BlockLog != "" {
		defaults.BlockLog = fc.BlockLog
	}
	return defaults, nil
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, v := range values {
		key := strings.ToLower(strings.TrimSpace(v))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, v)
	}
	return result
}
