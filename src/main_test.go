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
