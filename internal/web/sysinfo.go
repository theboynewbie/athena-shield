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
	if envSpeed := strings.TrimSpace(os.Getenv("HOST_NIC_SPEED")); envSpeed != "" {
		return "host", envSpeed, 0
	}

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
	for _, prefix := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "tailscale", "wg", "tun", "tap", "kube", "wl"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func scanSysClassNet(netDir string) (physName, physSpeedLabel string, physMbps int, fallbackUp string) {
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return "", "", 0, ""
	}

	for _, ent := range entries {
		name := ent.Name()
		if isVirtualNICName(name) {
			continue
		}
		base := filepath.Join(netDir, name)
		opBytes, err := os.ReadFile(filepath.Join(base, "operstate"))
		if err != nil || strings.TrimSpace(string(opBytes)) != "up" {
			continue
		}
		if fallbackUp == "" {
			fallbackUp = name
		}

		// Must be backed by a real hardware/PCI/virtio device
		if _, devErr := os.Stat(filepath.Join(base, "device")); devErr != nil {
			continue
		}

		// Exclude veth pairs (where iflink != ifindex)
		ifIdx, err1 := os.ReadFile(filepath.Join(base, "ifindex"))
		ifLnk, err2 := os.ReadFile(filepath.Join(base, "iflink"))
		if err1 == nil && err2 == nil && strings.TrimSpace(string(ifIdx)) != strings.TrimSpace(string(ifLnk)) {
			continue
		}

		// Exclude explicit virtual DEVTYPE in uevent
		if uev, err := os.ReadFile(filepath.Join(base, "uevent")); err == nil {
			uevStr := string(uev)
			if strings.Contains(uevStr, "DEVTYPE=veth") || strings.Contains(uevStr, "DEVTYPE=bridge") {
				continue
			}
		}

		spBytes, spErr := os.ReadFile(filepath.Join(base, "speed"))
		if spErr != nil {
			continue
		}
		mbps, err := strconv.Atoi(strings.TrimSpace(string(spBytes)))
		if err != nil || mbps <= 0 {
			continue
		}
		if mbps > physMbps {
			physMbps = mbps
			physName = name
			physSpeedLabel = formatNICSpeed(mbps)
		}
	}
	return physName, physSpeedLabel, physMbps, fallbackUp
}

func scanPCINetDevices(devicesDir string) (physName, physSpeedLabel string, physMbps int) {
	topEntries, err := os.ReadDir(devicesDir)
	if err != nil {
		return "", "", 0
	}

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > 5 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			name := ent.Name()
			if name == "power" || name == "iommu" || name == "iommu_group" || name == "subsystem" || name == "driver" || name == "firmware_node" {
				continue
			}
			full := filepath.Join(dir, name)
			if name == "net" {
				ifaces, err := os.ReadDir(full)
				if err != nil {
					continue
				}
				for _, iface := range ifaces {
					in := iface.Name()
					if isVirtualNICName(in) {
						continue
					}
					ifaceDir := filepath.Join(full, in)
					opBytes, err := os.ReadFile(filepath.Join(ifaceDir, "operstate"))
					if err != nil {
						continue
					}
					op := strings.TrimSpace(string(opBytes))
					if op != "up" {
						if op == "unknown" {
							carBytes, err := os.ReadFile(filepath.Join(ifaceDir, "carrier"))
							if err != nil || strings.TrimSpace(string(carBytes)) != "1" {
								continue
							}
						} else {
							continue
						}
					}
					spBytes, err := os.ReadFile(filepath.Join(ifaceDir, "speed"))
					if err != nil {
						continue
					}
					mbps, err := strconv.Atoi(strings.TrimSpace(string(spBytes)))
					if err != nil || mbps <= 0 {
						continue
					}
					if mbps > physMbps {
						physMbps = mbps
						physName = in
						physSpeedLabel = formatNICSpeed(mbps)
					}
				}
				continue
			}
			walk(full, depth+1)
		}
	}

	for _, ent := range topEntries {
		if ent.IsDir() && strings.HasPrefix(ent.Name(), "pci") {
			walk(filepath.Join(devicesDir, ent.Name()), 1)
		}
	}
	return physName, physSpeedLabel, physMbps
}

func readLinuxNIC() (string, string, int) {
	if name, label, mbps := scanPCINetDevices("/host/sys/devices"); name != "" {
		return name, label, mbps
	}
	if name, label, mbps := scanPCINetDevices("/sys/devices"); name != "" {
		return name, label, mbps
	}
	if name, label, mbps, _ := scanSysClassNet("/host/sys/class/net"); name != "" {
		return name, label, mbps
	}
	name, label, mbps, fallbackUp := scanSysClassNet("/sys/class/net")
	if name != "" {
		return name, label, mbps
	}
	if fallbackUp != "" {
		return fallbackUp, "Virtual NIC", 0
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
