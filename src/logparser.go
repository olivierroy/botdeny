package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Entry represents a single parsed access log line.
type Entry struct {
	ClientIP     string
	RemoteAddr   string
	ForwardedFor string
	UserIdent    string
	UserAuth     string
	Time         time.Time
	Method       string
	URI          string
	Protocol     string
	Status       int
	Bytes        int64
	Referer      string
	UserAgent    string
}

var (
	// Combined log format regex.
	logPattern = regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([^\]]+)\] "([A-Z]+) ([^" ]+) ([^"]+)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"(?: "([^"]*)")?`)
	timeLayout = "02/Jan/2006:15:04:05 -0700"
)

// ParseLine attempts to parse a single access log line.
func ParseLine(line string) (Entry, error) {
	matches := logPattern.FindStringSubmatch(line)
	if matches == nil {
		return Entry{}, fmt.Errorf("line does not match expected format: %w", ErrUnmatchedLine)
	}

	t, err := time.Parse(timeLayout, matches[4])
	if err != nil {
		return Entry{}, fmt.Errorf("parse time: %w", err)
	}

	status, err := strconv.Atoi(matches[8])
	if err != nil {
		return Entry{}, fmt.Errorf("parse status: %w", err)
	}

	var bytes int64
	if matches[9] != "-" {
		bytes, err = strconv.ParseInt(matches[9], 10, 64)
		if err != nil {
			return Entry{}, fmt.Errorf("parse bytes: %w", err)
		}
	}

	forwarded := ""
	if len(matches) >= 12 {
		forwarded = matches[12]
	}

	clientIP := deriveClientIP(matches[1], forwarded)

	return Entry{
		ClientIP:     clientIP,
		RemoteAddr:   matches[1],
		ForwardedFor: forwarded,
		UserIdent:    matches[2],
		UserAuth:     matches[3],
		Time:         t,
		Method:       matches[5],
		URI:          matches[6],
		Protocol:     matches[7],
		Status:       status,
		Bytes:        bytes,
		Referer:      matches[10],
		UserAgent:    matches[11],
	}, nil
}

// ErrUnmatchedLine signals that a log line could not be parsed using the known pattern.
var ErrUnmatchedLine = errors.New("unmatched line")

// Stream parses entries from a reader, yielding them via a channel until EOF or context cancellation.
func Stream(r io.Reader) (<-chan Entry, <-chan error) {
	entries := make(chan Entry)
	errs := make(chan error, 1)

	go func() {
		defer close(entries)
		defer close(errs)

		scanner := bufio.NewScanner(r)
		buf := make([]byte, 0, 1024*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			entry, err := ParseLine(line)
			if err != nil {
				errs <- err
				return
			}

			entries <- entry
		}

		if err := scanner.Err(); err != nil {
			errs <- err
			return
		}

		errs <- nil
	}()

	return entries, errs
}

func deriveClientIP(remoteAddr, forwarded string) string {
	forwarded = strings.TrimSpace(forwarded)
	if forwarded == "" || forwarded == "-" {
		return remoteAddr
	}

	parts := strings.Split(forwarded, ",")
	for _, part := range parts {
		ip := strings.TrimSpace(part)
		if ip != "" {
			return ip
		}
	}

	return remoteAddr
}
