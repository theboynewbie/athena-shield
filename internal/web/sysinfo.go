package web

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SystemMetrics struct {
	CPUPercent   float64 `json:"cpu_percent"`
	RAMPercent   float64 `json:"ram_percent"`
	RAMUsedGB    float64 `json:"ram_used_gb"`
	RAMTotalGB   float64 `json:"ram_total_gb"`
	NICName      string  `json:"nic_name"`
	NICSpeed     string  `json:"nic_speed"`
	NICSpeedMbps int     `json:"nic_speed_mbps"`
}

var (
	cpuMu      sync.Mutex
	prevIdle   uint64
	prevTotal  uint64
	hasPrevCPU bool

	nicMu        sync.Mutex
	cachedNIC    string
	cachedSpeed  string
	cachedMbps   int
	nicCachedAt  time.Time
)

func ReadSystemMetrics() SystemMetrics {
	nicName, nicSpeed, nicMbps := getCachedNICInfo()
	m := SystemMetrics{
		NICName:      nicName,
		NICSpeed:     nicSpeed,
		NICSpeedMbps: nicMbps,
	}
	if runtime.GOOS != "linux" {
		return m
	}
	m.CPUPercent = readLinuxCPU()
	m.RAMPercent, m.RAMUsedGB, m.RAMTotalGB = readLinuxRAM()
	return m
}

func formatNICSpeed(mbps int) string {
	if mbps <= 0 {
		return ""
	}
	if mbps >= 1000 {
		if mbps%1000 == 0 {
			return fmt.Sprintf("%dGbps", mbps/1000)
		}
		return fmt.Sprintf("%.1fGbps", float64(mbps)/1000.0)
	}
	return fmt.Sprintf("%dMbps", mbps)
}

func getCachedNICInfo() (name, speedLabel string, speedMbps int) {
	nicMu.Lock()
	if !nicCachedAt.IsZero() && time.Since(nicCachedAt) < 60*time.Second {
		n, s, m := cachedNIC, cachedSpeed, cachedMbps
		nicMu.Unlock()
		return n, s, m
	}
	nicMu.Unlock()

	if runtime.GOOS == "linux" {
		name, speedLabel, speedMbps = readLinuxNIC()
	} else {
		name, speedLabel, speedMbps = readGenericNIC()
	}

	nicMu.Lock()
	cachedNIC = name
	cachedSpeed = speedLabel
	cachedMbps = speedMbps
	nicCachedAt = time.Now()
	nicMu.Unlock()
	return name, speedLabel, speedMbps
}

func isVirtualNICName(name string) bool {
	if name == "lo" {
		return true
	}
	for _, prefix := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "tailscale", "wg", "tun", "tap", "kube"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func readLinuxNIC() (string, string, int) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", "Auto", 0
	}

	var bestPhysName, bestAnyName, fallbackUpName string
	var bestPhysSpeed, bestAnySpeed int

	for _, ent := range entries {
		name := ent.Name()
		if isVirtualNICName(name) {
			continue
		}
		base := filepath.Join("/sys/class/net", name)
		opBytes, err := os.ReadFile(filepath.Join(base, "operstate"))
		if err != nil || strings.TrimSpace(string(opBytes)) != "up" {
			continue
		}
		if fallbackUpName == "" {
			fallbackUpName = name
		}

		_, devErr := os.Stat(filepath.Join(base, "device"))
		isPhys := devErr == nil

		spBytes, spErr := os.ReadFile(filepath.Join(base, "speed"))
		if spErr != nil {
			continue
		}
		mbps, err := strconv.Atoi(strings.TrimSpace(string(spBytes)))
		if err != nil || mbps <= 0 {
			continue
		}
		if isPhys && mbps > bestPhysSpeed {
			bestPhysSpeed = mbps
			bestPhysName = name
		}
		if mbps > bestAnySpeed {
			bestAnySpeed = mbps
			bestAnyName = name
		}
	}

	if bestPhysName != "" {
		return bestPhysName, formatNICSpeed(bestPhysSpeed), bestPhysSpeed
	}
	if bestAnyName != "" {
		return bestAnyName, formatNICSpeed(bestAnySpeed), bestAnySpeed
	}
	if fallbackUpName != "" {
		return fallbackUpName, "Virtual NIC", 0
	}
	return "", "Auto", 0
}

func readGenericNIC() (string, string, int) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "Auto", 0
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		return iface.Name, "Auto", 0
	}
	return "", "Auto", 0
}

func readLinuxCPU() float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 {
		return 0
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}
	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if !hasPrevCPU {
		prevIdle = idle
		prevTotal = total
		hasPrevCPU = true
		return 0
	}
	dt := total - prevTotal
	di := idle - prevIdle
	prevTotal = total
	prevIdle = idle
	if dt == 0 {
		return 0
	}
	pct := float64(dt-di) / float64(dt) * 100.0
	return float64(int(pct*10)) / 10
}

func readLinuxRAM() (pct, usedGB, totalGB float64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0
	}
	var memTotalKB, memAvailKB uint64
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			memTotalKB, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemAvailable:":
			memAvailKB, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}
	if memTotalKB == 0 {
		return 0, 0, 0
	}
	usedKB := memTotalKB - memAvailKB
	totalGB = float64(int(float64(memTotalKB)/(1024*1024)*10)) / 10
	usedGB = float64(int(float64(usedKB)/(1024*1024)*10)) / 10
	pct = float64(int(float64(usedKB)/float64(memTotalKB)*1000)) / 10
	return pct, usedGB, totalGB
}
