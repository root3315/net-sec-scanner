package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"net-sec-scanner/report"
	"net-sec-scanner/scanner"
)

const (
	version       = "1.0.0"
	defaultTimeout = 2 * time.Second
)

var (
	targetHost   string
	targetPorts  string
	portRange    string
	timeoutSec   int
	concurrency  int
	maxRetries   int
	outputFormat string
	outputFile   string
	verbose      bool
	showVersion  bool
	serviceDetect bool
	vulnCheck    bool
)

func init() {
	flag.StringVar(&targetHost, "host", "", "Target host IP address or hostname (required)")
	flag.StringVar(&targetPorts, "ports", "", "Comma-separated list of ports to scan")
	flag.StringVar(&portRange, "range", "", "Port range to scan (e.g., 1-1000)")
	flag.IntVar(&timeoutSec, "timeout", 2, "Connection timeout in seconds")
	flag.IntVar(&concurrency, "concurrency", 50, "Number of concurrent connections")
	flag.IntVar(&maxRetries, "max-retries", 3, "Maximum retry attempts for connection timeouts")
	flag.StringVar(&outputFormat, "format", "text", "Output format: text, json, csv")
	flag.StringVar(&outputFile, "output", "", "Output file path (default: stdout)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.BoolVar(&serviceDetect, "service-detect", false, "Detect services on open ports")
	flag.BoolVar(&vulnCheck, "vuln-check", false, "Check for known vulnerabilities")
}

func main() {
	flag.Parse()

	if showVersion {
		fmt.Printf("net-sec-scanner version %s\n", version)
		return
	}

	if targetHost == "" {
		fmt.Fprintf(os.Stderr, "Error: target host is required\n")
		printUsage()
		os.Exit(1)
	}

	if targetPorts == "" && portRange == "" {
		portRange = "1-1024"
	}

	timeout := time.Duration(timeoutSec) * time.Second

	ports, err := parsePorts(targetPorts, portRange)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing ports: %v\n", err)
		os.Exit(1)
	}

	if len(ports) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no ports specified for scanning\n")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Starting net-sec-scanner v%s\n", version)
		fmt.Printf("Target: %s\n", targetHost)
		fmt.Printf("Ports: %d ports to scan\n", len(ports))
		fmt.Printf("Timeout: %v\n", timeout)
		fmt.Printf("Concurrency: %d\n", concurrency)
		fmt.Printf("Max Retries: %d\n", maxRetries)
		fmt.Println(strings.Repeat("-", 50))
	}

	ipAddr, err := resolveHost(targetHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving host: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Resolved %s to %s\n", targetHost, ipAddr)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	scannerConfig := scanner.Config{
		TargetIP:      ipAddr,
		Ports:         ports,
		Timeout:       timeout,
		Concurrency:   concurrency,
		Verbose:       verbose,
		ServiceDetect: serviceDetect,
		MaxRetries:    maxRetries,
	}

	netScanner := scanner.NewNetworkScanner(scannerConfig)

	go func() {
		<-sigChan
		if verbose {
			fmt.Println("\nReceived interrupt signal, stopping scan...")
		}
		netScanner.Stop()
		os.Exit(1)
	}()

	results, err := netScanner.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	vulnerabilities := []report.Vulnerability{}
	if vulnCheck && len(results.OpenPorts) > 0 {
		if verbose {
			fmt.Println("\nChecking for known vulnerabilities...")
		}
		vulnerabilities = checkVulnerabilities(results.OpenPorts)
	}

	reportData := report.ReportData{
		Target:          targetHost,
		TargetIP:        ipAddr,
		ScanTime:        time.Now(),
		OpenPorts:       results.OpenPorts,
		ClosedPorts:     results.ClosedPorts,
		FilteredPorts:   results.FilteredPorts,
		Vulnerabilities: vulnerabilities,
	}

	reportOutput, err := generateReport(reportData, outputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating report: %v\n", err)
		os.Exit(1)
	}

	if outputFile != "" {
		err = os.WriteFile(outputFile, []byte(reportOutput), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		if verbose {
			fmt.Printf("Report saved to: %s\n", outputFile)
		}
	} else {
		fmt.Println(reportOutput)
	}

	printSummary(results)
}

func parsePorts(portList, portRange string) ([]int, error) {
	portSet := make(map[int]bool)

	if portList != "" {
		parts := strings.Split(portList, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.Contains(part, "-") {
				rangePorts, err := expandRange(part)
				if err != nil {
					return nil, err
				}
				for _, p := range rangePorts {
					portSet[p] = true
				}
			} else {
				port, err := strconv.Atoi(part)
				if err != nil {
					return nil, fmt.Errorf("invalid port: %s", part)
				}
				if port < 1 || port > 65535 {
					return nil, fmt.Errorf("port out of range: %d", port)
				}
				portSet[port] = true
			}
		}
	}

	if portRange != "" {
		rangePorts, err := expandRange(portRange)
		if err != nil {
			return nil, err
		}
		for _, p := range rangePorts {
			portSet[p] = true
		}
	}

	ports := make([]int, 0, len(portSet))
	for port := range portSet {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	return ports, nil
}

func expandRange(rangeStr string) ([]int, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", rangeStr)
	}

	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid start port: %s", parts[0])
	}

	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid end port: %s", parts[1])
	}

	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		return nil, fmt.Errorf("ports must be between 1 and 65535")
	}

	if start > end {
		start, end = end, start
	}

	ports := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}

	return ports, nil
}

func resolveHost(host string) (string, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			return ip.String(), nil
		}
		return ip.String(), nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	if len(ips) > 0 {
		return ips[0].String(), nil
	}

	return "", fmt.Errorf("no IP address found for host: %s", host)
}

func checkVulnerabilities(openPorts []scanner.PortResult) []report.Vulnerability {
	var vulns []report.Vulnerability

	wellKnownVulns := map[int]report.Vulnerability{
		21:  {Port: 21, Service: "FTP", Severity: "HIGH", Description: "FTP allows cleartext authentication"},
		23:  {Port: 23, Service: "Telnet", Severity: "CRITICAL", Description: "Telnet transmits data in cleartext"},
		25:  {Port: 25, Service: "SMTP", Severity: "MEDIUM", Description: "SMTP may allow relay abuse"},
		110: {Port: 110, Service: "POP3", Severity: "HIGH", Description: "POP3 uses cleartext authentication"},
		139: {Port: 139, Service: "NetBIOS", Severity: "HIGH", Description: "NetBIOS may expose system information"},
		445: {Port: 445, Service: "SMB", Severity: "CRITICAL", Description: "SMB vulnerable to various exploits"},
		3306: {Port: 3306, Service: "MySQL", Severity: "MEDIUM", Description: "Database port exposed to network"},
		5432: {Port: 5432, Service: "PostgreSQL", Severity: "MEDIUM", Description: "Database port exposed to network"},
		6379: {Port: 6379, Service: "Redis", Severity: "HIGH", Description: "Redis often misconfigured without auth"},
		27017: {Port: 27017, Service: "MongoDB", Severity: "HIGH", Description: "MongoDB may be exposed without auth"},
	}

	for _, portResult := range openPorts {
		if vuln, exists := wellKnownVulns[portResult.Port]; exists {
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

func generateReport(data report.ReportData, format string) (string, error) {
	switch strings.ToLower(format) {
	case "json":
		return report.ToJSON(data)
	case "csv":
		return report.ToCSV(data)
	default:
		return report.ToText(data)
	}
}

func printSummary(results scanner.ScanResults) {
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("Scan Summary:\n")
	fmt.Printf("  Open ports:     %d\n", len(results.OpenPorts))
	fmt.Printf("  Closed ports:   %d\n", len(results.ClosedPorts))
	fmt.Printf("  Filtered ports: %d\n", len(results.FilteredPorts))

	if len(results.OpenPorts) > 0 {
		fmt.Println("\nOpen Ports:")
		for _, port := range results.OpenPorts {
			service := port.Service
			if service == "" {
				service = scanner.IdentifyService(port.Port, nil)
			}
			if port.Banner != "" {
				fmt.Printf("  %d/tcp\t%s\t[%s]\n", port.Port, service, port.Banner)
			} else {
				fmt.Printf("  %d/tcp\t%s\n", port.Port, service)
			}
		}
	}
}

func printUsage() {
	fmt.Println("Usage: net-sec-scanner [options]")
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  net-sec-scanner -host 192.168.1.1")
	fmt.Println("  net-sec-scanner -host example.com -ports 80,443,8080")
	fmt.Println("  net-sec-scanner -host 192.168.1.1 -range 1-1000 -service-detect")
	fmt.Println("  net-sec-scanner -host 192.168.1.1 -vuln-check -format json")
}
