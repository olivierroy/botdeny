package main

import (
	"testing"
	"time"
)

func TestAnalyzerFlagsSuspiciousIP(t *testing.T) {
	cfg := Config{
		MinRequests:         1,
		MaxAverageRPM:       0,
		MaxBurstWindow:      time.Minute,
		MaxBurstRequests:    1000,
		Min404Errors:        0,
		MinErrorRatio:       0,
		MinUniquePaths:      1,
		ScoreThreshold:      2,
		WhitelistAgents:     nil,
		MinPHP404s:          0,
		SuspiciousCountries: nil,
	}

	analyzer := New(cfg, nil)
	now := time.Now()
	analyzer.Process(Entry{
		ClientIP:   "1.1.1.1",
		RemoteAddr: "1.1.1.1",
		Time:       now,
		URI:        "/index.html",
		Status:     200,
	})

	suspects := analyzer.Suspicious()
	if len(suspects) != 1 {
		t.Fatalf("expected 1 suspect, got %d", len(suspects))
	}
	if suspects[0].IP != "1.1.1.1" {
		t.Fatalf("unexpected IP reported: %s", suspects[0].IP)
	}
}

func TestAnalyzerRespectsAllowedIPs(t *testing.T) {
	cfg := Config{
		MinRequests:         1,
		MaxAverageRPM:       0,
		MaxBurstWindow:      time.Minute,
		MaxBurstRequests:    10,
		Min404Errors:        0,
		MinErrorRatio:       0,
		MinUniquePaths:      1,
		ScoreThreshold:      1,
		WhitelistAgents:     nil,
		MinPHP404s:          0,
		SuspiciousCountries: nil,
		AllowedIPs:          []string{"2.2.2.2"},
	}

	analyzer := New(cfg, nil)
	analyzer.Process(Entry{
		ClientIP:   "2.2.2.2",
		RemoteAddr: "2.2.2.2",
		Time:       time.Now(),
		URI:        "/path",
		Status:     200,
	})

	suspects := analyzer.Suspicious()
	if len(suspects) != 0 {
		t.Fatalf("expected no suspects for allowed ip, got %d", len(suspects))
	}
}

func TestAnalyzerWhitelistedUserAgent(t *testing.T) {
	cfg := Config{
		MinRequests:         1,
		MaxAverageRPM:       0,
		MaxBurstWindow:      time.Minute,
		MaxBurstRequests:    10,
		Min404Errors:        0,
		MinErrorRatio:       0,
		MinUniquePaths:      1,
		ScoreThreshold:      1,
		WhitelistAgents:     []string{"Preload"},
		MinPHP404s:          0,
		SuspiciousCountries: nil,
	}

	analyzer := New(cfg, nil)
	analyzer.Process(Entry{
		ClientIP:   "3.3.3.3",
		RemoteAddr: "3.3.3.3",
		Time:       time.Now(),
		URI:        "/",
		Status:     200,
		UserAgent:  "Example Preload bot",
	})

	suspects := analyzer.Suspicious()
	if len(suspects) != 0 {
		t.Fatalf("expected no suspects for whitelisted user agent")
	}
}

func TestAnalyzerAllowedCIDR(t *testing.T) {
	cfg := Config{
		MinRequests:         1,
		MaxAverageRPM:       0,
		MaxBurstWindow:      time.Minute,
		MaxBurstRequests:    10,
		Min404Errors:        0,
		MinErrorRatio:       0,
		MinUniquePaths:      1,
		ScoreThreshold:      1,
		WhitelistAgents:     nil,
		MinPHP404s:          0,
		SuspiciousCountries: nil,
		AllowedCIDRs:        []string{"203.0.113.0/24"},
	}

	analyzer := New(cfg, nil)
	analyzer.Process(Entry{
		ClientIP:   "203.0.113.55",
		RemoteAddr: "203.0.113.55",
		Time:       time.Now(),
		URI:        "/",
		Status:     200,
	})

	suspects := analyzer.Suspicious()
	if len(suspects) != 0 {
		t.Fatalf("expected no suspects for allowed cidr")
	}
}
