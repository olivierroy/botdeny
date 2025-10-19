package main

import (
    "strings"
    "testing"
    "time"
)

func TestParseLineCombinedFormat(t *testing.T) {
    line := "35.191.50.44 - - [19/Oct/2025:00:00:07 +0200] \"GET /files/colors/5405.jpg HTTP/1.1\" 304 0 \"https://www.wordans.at/\" \"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36\""

    entry, err := ParseLine(line)
    if err != nil {
        t.Fatalf("ParseLine returned error: %v", err)
    }

    if entry.RemoteAddr != "35.191.50.44" {
        t.Fatalf("unexpected remote addr: %s", entry.RemoteAddr)
    }
    if entry.ClientIP != "35.191.50.44" {
        t.Fatalf("unexpected client ip: %s", entry.ClientIP)
    }
    wantTime, _ := time.Parse("02/Jan/2006:15:04:05 -0700", "19/Oct/2025:00:00:07 +0200")
    if !entry.Time.Equal(wantTime) {
        t.Fatalf("unexpected time: %v", entry.Time)
    }
    if entry.Method != "GET" {
        t.Fatalf("unexpected method: %s", entry.Method)
    }
    if entry.URI != "/files/colors/5405.jpg" {
        t.Fatalf("unexpected uri: %s", entry.URI)
    }
    if entry.Status != 304 {
        t.Fatalf("unexpected status: %d", entry.Status)
    }
    if entry.UserAgent == "" {
        t.Fatalf("expected user agent to be populated")
    }
}

func TestParseLineWithForwardedFor(t *testing.T) {
    line := "203.0.113.10 - - [19/Oct/2025:00:01:00 +0000] \"GET / HTTP/1.1\" 200 1024 \"-\" \"UA\" \"198.51.100.5, 203.0.113.10\""

    entry, err := ParseLine(line)
    if err != nil {
        t.Fatalf("ParseLine returned error: %v", err)
    }

    if entry.ClientIP != "198.51.100.5" {
        t.Fatalf("expected forwarded client IP, got %s", entry.ClientIP)
    }
    if entry.ForwardedFor == "" {
        t.Fatalf("expected forwarded for header to be captured")
    }
}

func TestParseLineInvalid(t *testing.T) {
    _, err := ParseLine("invalid log line")
    if err == nil {
        t.Fatalf("expected error for invalid log line")
    }
}

func TestStreamStopsOnParseError(t *testing.T) {
    logs := strings.NewReader("192.0.2.10 - - [19/Oct/2025:00:00:07 +0200] \"GET / HTTP/1.1\" 200 0 \"-\" \"agent\"\ninvalid line")

    entries, errs := Stream(logs)
    // Drain first entry which should fail to parse due to bad IP token.
    for range entries {
    }
    if err := <-errs; err == nil {
        t.Fatalf("expected error from stream")
    }
}
