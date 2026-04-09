package security

// This file contains functions to manage iptables rules for network isolation of the containers.

import (
	"fmt"
	"os/exec"
)

// Regras de firewall para isolar o container (apenas acesso a localhost e rede interna do docker)
// Problema: bloqueia todos os containers
// Talvez possa ser usado como um failsafe, ou um modo de Lockdown geral.

// createIptablesIsolationRules applies iptables rules to block external network access by default
// Only allows internal docker traffic (172.17.0.0/16 on docker0 interface)
func CreateIptablesIsolationRules() {
	// Rule: Block everything except docker internal network (172.17.0.0/16)
	rule := "iptables -I DOCKER-USER -i docker0 ! -d 172.17.0.0/16 -j DROP"

	cmd := exec.Command("sh", "-c", rule)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Warning: Could not apply iptables isolation rule: %v\n", err)
		fmt.Println("Make sure you're running with sudo or appropriate privileges")
	} else {
		fmt.Println("Network isolation rule applied (localhost only)")
	}
}

// AllowNetworkAccess removes the isolation rule and allows full network access
// Use this when container needs to install/update packages or access external APIs
func AllowNetworkAccess() {

	// Remove the isolation rule
	rule := "iptables -D DOCKER-USER -i docker0 ! -d 172.17.0.0/16 -j DROP"

	cmd := exec.Command("sh", "-c", rule)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Warning: Could not remove iptables isolation rule: %v\n", err)
	} else {
		fmt.Println("Network access allowed")
	}
}

// AllowNetworkAccessToEndpoint allows access to specific endpoint (IP:port)
// Example: AllowNetworkAccessToEndpoint("93.184.216.34", "443")
func AllowNetworkAccessToEndpoint(ip, port string) {
	rule := fmt.Sprintf("iptables -I DOCKER-USER -i docker0 -d %s -p tcp --dport %s -j ACCEPT", ip, port)

	cmd := exec.Command("sh", "-c", rule)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error: Could not allow access to %s:%s - %v\n", ip, port, err)
	} else {
		fmt.Printf("Access allowed to %s:%s\n", ip, port)
	}
}

// FULL NETWORK BLOCK
func BlockAllNetworkAccess() {

	AllowNetworkAccess() // Remove any previous rules to ensure a clean state before blocking all access

	rule := "iptables -I DOCKER-USER -i docker0 -j DROP"

	cmd := exec.Command("sh", "-c", rule)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error: Could not block all network access - %v\n", err)
	} else {
		fmt.Println("All network access blocked")
	}
}

// ListIptablesRules shows current iptables rules in DOCKER-USER chain
func ListIptablesRules() {
	cmd := exec.Command("sh", "-c", "iptables -L DOCKER-USER -v -n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error: Could not list iptables rules - %v\n", err)
		return
	}

	fmt.Println("\nCurrent DOCKER-USER chain rules:")
	fmt.Println(string(output))
}

func RemoveIptablesRules() {
	// Remove all rules in DOCKER-USER chain (use with caution, affects all containers)
	rule := "iptables -F DOCKER-USER"

	cmd := exec.Command("sh", "-c", rule)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error: Could not remove iptables rules - %v\n", err)
	} else {
		fmt.Println("All iptables rules in DOCKER-USER chain removed")
	}
}
