package main

import (
	"net"

	geoip2 "github.com/oschwald/geoip2-golang"
)

// GeoLookup resolves GeoIP metadata for an IP address.
type GeoLookup func(ip string) (GeoInfo, bool)

// GeoInfo minimal geo metadata for reporting.
type GeoInfo struct {
	CountryISO  string
	CountryName string
}

// newGeoLookup opens a MaxMind-compatible database and returns a lookup function plus closer.
func newGeoLookup(path string) (GeoLookup, func() error, error) {
	reader, err := geoip2.Open(path)
	if err != nil {
		return nil, nil, err
	}

	lookup := func(ip string) (GeoInfo, bool) {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return GeoInfo{}, false
		}

		record, err := reader.Country(parsed)
		if err != nil {
			return GeoInfo{}, false
		}

		info := GeoInfo{}
		if record != nil {
			if record.Country.IsoCode != "" {
				info.CountryISO = record.Country.IsoCode
			}
			if name, ok := record.Country.Names["en"]; ok {
				info.CountryName = name
			}
		}
		if info.CountryISO == "" && info.CountryName == "" {
			return GeoInfo{}, false
		}
		return info, true
	}

	closer := func() error {
		return reader.Close()
	}

	return lookup, closer, nil
}
