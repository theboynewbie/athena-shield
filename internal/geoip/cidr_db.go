package geoip

import (
	"encoding/binary"
	"encoding/csv"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type ipv4Range struct {
	start   uint32
	end     uint32
	cc      string
	country string
}

type ipv6Range struct {
	net     *net.IPNet
	cc      string
	country string
}

var (
	geoDBMu  sync.RWMutex
	v4Ranges []ipv4Range
	v6Ranges []ipv6Range
)

func ipv4ToUint32(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

func cidrToIPv4Range(cidr *net.IPNet) (uint32, uint32, bool) {
	base, ok := ipv4ToUint32(cidr.IP)
	if !ok || len(cidr.Mask) != 4 {
		return 0, 0, false
	}
	mask := binary.BigEndian.Uint32(cidr.Mask)
	start := base & mask
	end := start | ^mask
	return start, end, true
}

// ResetOfflineGeoIP clears the in-memory offline GeoIP ranges and cache.
func ResetOfflineGeoIP() {
	geoDBMu.Lock()
	v4Ranges = nil
	v6Ranges = nil
	geoDBMu.Unlock()

	cacheMu.Lock()
	geoCache = make(map[string][2]string)
	cacheMu.Unlock()
}

// LoadGeoIPCSV loads an offline GeoIP CSV database supporting both:
//   - CIDR format: cidr,CC[,CountryName]
//   - IP2Location LITE IPv4 format: startUint32,endUint32,CC[,CountryName]
func LoadGeoIPCSV(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	var nextV4 []ipv4Range
	var nextV6 []ipv6Range

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(rec) < 2 {
			continue
		}
		first := strings.TrimSpace(rec[0])
		if first == "" || strings.HasPrefix(first, "#") {
			continue
		}

		// Format 1: CIDR,CC[,Country]
		if strings.Contains(first, "/") {
			_, cidr, parseErr := net.ParseCIDR(first)
			if parseErr != nil {
				continue
			}
			cc := strings.ToUpper(strings.TrimSpace(rec[1]))
			if len(cc) != 2 || !isASCIIAlpha(cc[0]) || !isASCIIAlpha(cc[1]) {
				continue
			}
			cn := cc
			if len(rec) >= 3 && strings.TrimSpace(rec[2]) != "" {
				cn = strings.TrimSpace(rec[2])
			}
			if start, end, ok := cidrToIPv4Range(cidr); ok {
				nextV4 = append(nextV4, ipv4Range{start: start, end: end, cc: cc, country: cn})
			} else {
				nextV6 = append(nextV6, ipv6Range{net: cidr, cc: cc, country: cn})
			}
			continue
		}

		// Format 2: IP2Location LITE IPv4 integer range: start,end,CC[,Country]
		if len(rec) >= 3 {
			sVal, err1 := strconv.ParseUint(first, 10, 64)
			eVal, err2 := strconv.ParseUint(strings.TrimSpace(rec[1]), 10, 64)
			if err1 != nil || err2 != nil || sVal > 0xFFFFFFFF || eVal > 0xFFFFFFFF || sVal > eVal {
				continue
			}
			cc := strings.ToUpper(strings.TrimSpace(rec[2]))
			if len(cc) != 2 || !isASCIIAlpha(cc[0]) || !isASCIIAlpha(cc[1]) {
				continue
			}
			cn := cc
			if len(rec) >= 4 && strings.TrimSpace(rec[3]) != "" {
				cn = strings.TrimSpace(rec[3])
			}
			nextV4 = append(nextV4, ipv4Range{start: uint32(sVal), end: uint32(eVal), cc: cc, country: cn})
		}
	}

	sort.Slice(nextV4, func(i, j int) bool {
		if nextV4[i].start == nextV4[j].start {
			return nextV4[i].end < nextV4[j].end
		}
		return nextV4[i].start < nextV4[j].start
	})

	geoDBMu.Lock()
	v4Ranges = nextV4
	v6Ranges = nextV6
	geoDBMu.Unlock()

	cacheMu.Lock()
	geoCache = make(map[string][2]string)
	cacheMu.Unlock()

	return len(nextV4) + len(nextV6), nil
}

func lookupOfflineDB(ip net.IP) (string, string, bool) {
	if ip == nil {
		return "", "", false
	}
	geoDBMu.RLock()
	defer geoDBMu.RUnlock()

	if val, ok := ipv4ToUint32(ip); ok {
		if len(v4Ranges) == 0 {
			return "", "", false
		}
		idx := sort.Search(len(v4Ranges), func(i int) bool {
			return v4Ranges[i].start > val
		})
		if idx > 0 {
			cand := v4Ranges[idx-1]
			if val >= cand.start && val <= cand.end {
				return cand.cc, cand.country, true
			}
		}
		return "", "", false
	}

	for _, r := range v6Ranges {
		if r.net.Contains(ip) {
			return r.cc, r.country, true
		}
	}
	return "", "", false
}
