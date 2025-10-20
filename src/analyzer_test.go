package main

import (
	"strings"
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

func TestAnalyzerRespectsMinRequestsEvenForCountryPenalty(t *testing.T) {
	geo := func(ip string) (GeoInfo, bool) {
		return GeoInfo{CountryISO: "CN", CountryName: "China"}, true
	}

	cfg := Config{
		MinRequests:         10,
		MaxAverageRPM:       0,
		MaxBurstWindow:      time.Minute,
		MaxBurstRequests:    10,
		Min404Errors:        0,
		MinErrorRatio:       0,
		MinUniquePaths:      1,
		ScoreThreshold:      1,
		WhitelistAgents:     nil,
		MinPHP404s:          0,
		SuspiciousCountries: []string{"CN"},
	}

	analyzer := New(cfg, geo)
	for i := 0; i < 5; i++ {
		analyzer.Process(Entry{
			ClientIP:   "5.5.5.5",
			RemoteAddr: "5.5.5.5",
			Time:       time.Now().Add(time.Duration(i) * time.Second),
			URI:        "/",
			Status:     200,
		})
	}

	suspects := analyzer.Suspicious()
	if len(suspects) != 0 {
		t.Fatalf("expected no suspects when request count below min threshold, got %d", len(suspects))
	}
}

func TestAnalyzerSQLInjection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinRequests = 1
	cfg.ScoreThreshold = 1
	cfg.MinSQLInjections = 3

	a := New(cfg, nil)

	// Regular requests
	a.Process(Entry{
		Time:       time.Now(),
		ClientIP:   "1.2.3.4",
		RemoteAddr: "1.2.3.4",
		Status:     200,
		URI:        "/products?page=1",
	})
	a.Process(Entry{
		Time:       time.Now(),
		ClientIP:   "1.2.3.4",
		RemoteAddr: "1.2.3.4",
		Status:     200,
		URI:        "/products?page=2",
	})

	// SQL injection attempts
	a.Process(Entry{
		Time:       time.Now(),
		ClientIP:   "1.2.3.4",
		RemoteAddr: "1.2.3.4",
		Status:     403,
		URI:        "/page?id=1' OR '1'='1",
	})
	a.Process(Entry{
		Time:       time.Now(),
		ClientIP:   "1.2.3.4",
		RemoteAddr: "1.2.3.4",
		Status:     403,
		URI:        "/page?id=1 UNION SELECT * FROM users--",
	})
	a.Process(Entry{
		Time:       time.Now(),
		ClientIP:   "1.2.3.4",
		RemoteAddr: "1.2.3.4",
		Status:     403,
		URI:        "/page?id=1 AND 1=1; pg_sleep(5)",
	})

	suspects := a.Suspicious()
	if len(suspects) != 1 {
		t.Fatalf("expected 1 suspect, got %d", len(suspects))
	}

	found := false
	for _, reason := range suspects[0].Reasons {
		if strings.Contains(reason, "SQL injection") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected SQL injection reason, got %v", suspects[0].Reasons)
	}

	stat := suspects[0].Stats
	if stat.SQLInjections != 3 {
		t.Errorf("expected 3 SQL injections, got %d", stat.SQLInjections)
	}
}

func TestAnalyzerAllowedURI(t *testing.T) {
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
		AllowedURIs:         []string{"/whitelist"},
	}

	analyzer := New(cfg, nil)
	for i := 0; i < 5; i++ {
		analyzer.Process(Entry{
			ClientIP:   "6.6.6.6",
			RemoteAddr: "6.6.6.6",
			Time:       time.Now().Add(time.Duration(i) * time.Second),
			URI:        "/whitelist/path",
			Status:     200,
		})
	}

	suspects := analyzer.Suspicious()
	if len(suspects) != 0 {
		t.Fatalf("expected no suspects when requests hit allowed uri")
	}
}
