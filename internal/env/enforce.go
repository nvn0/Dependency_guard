package env

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"Dependency_guard/internal/ebpf"
	"Dependency_guard/internal/env/utils"
)

func containerDNSServers(pid int) ([]net.IP, error) {
	path := fmt.Sprintf("/proc/%d/root/etc/resolv.conf", pid)

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var servers []net.IP
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			address := strings.SplitN(fields[1], "%", 2)[0]
			if ip := net.ParseIP(address); ip != nil {
				servers = append(servers, ip)
			}
		}
	}

	return servers, scanner.Err()
}

func ipsToStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

func Enforce(projectName string) {
	_, containerID, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project info: %v\n", err)
		return
	}

	config, err := utils.GetConfigInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project config: %v\n", err)
		return
	}
	if !config.Ebpf.Enabled {
		fmt.Println("eBPF enforcement is disabled in the project config")
		return
	}

	containerPIDText, err := utils.GetContainerPID(containerID)
	if err != nil {
		fmt.Printf("Error getting container PID: %v\n", err)
		return
	}
	containerPID, err := strconv.Atoi(containerPIDText)
	if err != nil {
		fmt.Printf("Error parsing container PID %q: %v\n", containerPIDText, err)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dnsServers, err := containerDNSServers(containerPID)
	if err != nil {
		fmt.Printf("Error getting the container (PID %q) DNS servers: %v\n", containerPIDText, err)
		return
	}

	dnsServerStrings := ipsToStrings(dnsServers)
	fmt.Println("Container DNS servers:")
	for _, dns := range dnsServerStrings {
      fmt.Println(dns)
  	}

	enforcer, err := ebpf.StartNetworkEnforcer(ctx, ebpf.EnforcerConfig{
		ContainerPID:     containerPID,
		NetworkWhitelist: config.Ebpf.Whitelist,
	}, dnsServerStrings)
	if err != nil {
		fmt.Printf("Error starting eBPF network enforcement: %v\n", err)
		return
	}
	defer enforcer.Close()

	fmt.Printf("Enforcing network whitelist for project %s with container PID %d. Press Ctrl+C to stop.\n", projectName, containerPID)
	<-ctx.Done()
	fmt.Println("\nStopping eBPF network enforcement")
}
