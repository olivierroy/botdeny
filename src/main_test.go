package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAllowIPsFromFiles(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "trusted.conf")
	content := `# Cloudflare ranges
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 127.0.0.1;
real_ip_header CF-Connecting-IP;
`
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	ips, cidrs, err := loadAllowIPsFromFiles([]string{filePath})
	if err != nil {
		t.Fatalf("loadAllowIPsFromFiles: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "173.245.48.0/20" {
		t.Fatalf("unexpected cidrs: %v", cidrs)
	}
	if len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Fatalf("unexpected ips: %v", ips)
	}
}

func TestApplyConfigDefaultsSensitiveURLs(t *testing.T) {
	cfg := DefaultConfig()
	fc := FileConfig{
		SensitiveURLs: []PathLimit{
			{Prefix: "/sign_in", Threshold: 5},
			{Prefix: "/admin/login", Threshold: 3},
		},
	}

	if err := applyConfigDefaults(&cfg, fc); err != nil {
		t.Fatalf("applyConfigDefaults: %v", err)
	}

	if len(cfg.SensitiveURLLimits) != 2 {
		t.Fatalf("expected 2 sensitive url limits, got %d", len(cfg.SensitiveURLLimits))
	}
	if cfg.SensitiveURLLimits[0].Prefix != "/sign_in" || cfg.SensitiveURLLimits[0].Threshold != 5 {
		t.Fatalf("unexpected first sensitive url limit: %+v", cfg.SensitiveURLLimits[0])
	}
}
