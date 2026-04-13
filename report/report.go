package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net-sec-scanner/scanner"
	"strings"
	"time"
)

type Vulnerability struct {
	Port        int    `json:"port"`
	Service     string `json:"service"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type ReportData struct {
	Target          string              `json:"target"`
	TargetIP        string              `json:"target_ip"`
	ScanTime        time.Time           `json:"scan_time"`
	OpenPorts       []scanner.PortResult `json:"open_ports"`
	ClosedPorts     []scanner.PortResult `json:"closed_ports"`
	FilteredPorts   []scanner.PortResult `json:"filtered_ports"`
	Vulnerabilities []Vulnerability     `json:"vulnerabilities,omitempty"`
}

type PortRecord struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Service string `json:"service"`
	Latency string `json:"latency"`
}

type JSONReport struct {
	Target          string        `json:"target"`
	TargetIP        string        `json:"target_ip"`
	ScanTime        string        `json:"scan_time"`
	ScanDuration    string        `json:"scan_duration,omitempty"`
	OpenPorts       []PortRecord  `json:"open_ports"`
	ClosedPorts     []PortRecord  `json:"closed_ports"`
	FilteredPorts   []PortRecord  `json:"filtered_ports"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Summary         Summary       `json:"summary"`
}

type Summary struct {
	TotalOpen     int `json:"total_open"`
	TotalClosed   int `json:"total_closed"`
	TotalFiltered int `json:"total_filtered"`
	TotalVulns    int `json:"total_vulnerabilities"`
	CriticalVulns int `json:"critical_vulnerabilities"`
	HighVulns     int `json:"high_vulnerabilities"`
	MediumVulns   int `json:"medium_vulnerabilities"`
}

func ToJSON(data ReportData) (string, error) {
	report := JSONReport{
		Target:   data.Target,
		TargetIP: data.TargetIP,
		ScanTime: data.ScanTime.Format(time.RFC3339),
	}

	report.OpenPorts = convertToPortRecords(data.OpenPorts)
	report.ClosedPorts = convertToPortRecords(data.ClosedPorts)
	report.FilteredPorts = convertToPortRecords(data.FilteredPorts)
	report.Vulnerabilities = data.Vulnerabilities

	report.Summary = Summary{
		TotalOpen:     len(data.OpenPorts),
		TotalClosed:   len(data.ClosedPorts),
		TotalFiltered: len(data.FilteredPorts),
		TotalVulns:    len(data.Vulnerabilities),
	}

	for _, vuln := range data.Vulnerabilities {
		switch strings.ToUpper(vuln.Severity) {
		case "CRITICAL":
			report.Summary.CriticalVulns++
		case "HIGH":
			report.Summary.HighVulns++
		case "MEDIUM":
			report.Summary.MediumVulns++
		}
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

func convertToPortRecords(ports []scanner.PortResult) []PortRecord {
	records := make([]PortRecord, len(ports))
	for i, port := range ports {
		service := port.Service
		if service == "" {
			service = scanner.IdentifyService(port.Port, nil, 2*time.Second)
		}
		records[i] = PortRecord{
			Port:    port.Port,
			Status:  port.Status.String(),
			Service: service,
			Latency: port.Latency.String(),
		}
	}
	return records
}

func ToText(data ReportData) (string, error) {
	var sb strings.Builder

	sb.WriteString("========================================\n")
	sb.WriteString("     NETWORK SECURITY SCAN REPORT      \n")
	sb.WriteString("========================================\n\n")

	sb.WriteString(fmt.Sprintf("Target:      %s (%s)\n", data.Target, data.TargetIP))
	sb.WriteString(fmt.Sprintf("Scan Time:   %s\n", data.ScanTime.Format("2006-01-02 15:04:05")))
	sb.WriteString("\n")

	sb.WriteString("----------------------------------------\n")
	sb.WriteString("                 SUMMARY                \n")
	sb.WriteString("----------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Open Ports:      %d\n", len(data.OpenPorts)))
	sb.WriteString(fmt.Sprintf("Closed Ports:    %d\n", len(data.ClosedPorts)))
	sb.WriteString(fmt.Sprintf("Filtered Ports:  %d\n", len(data.FilteredPorts)))
	sb.WriteString(fmt.Sprintf("Vulnerabilities: %d\n", len(data.Vulnerabilities)))
	sb.WriteString("\n")

	if len(data.OpenPorts) > 0 {
		sb.WriteString("----------------------------------------\n")
		sb.WriteString("              OPEN PORTS                \n")
		sb.WriteString("----------------------------------------\n")
		sb.WriteString(fmt.Sprintf("%-8s %-15s %-12s %s\n", "PORT", "STATUS", "SERVICE", "LATENCY"))
		sb.WriteString(strings.Repeat("-", 55) + "\n")

		for _, port := range data.OpenPorts {
			service := port.Service
			if service == "" {
				service = scanner.IdentifyService(port.Port, nil, 2*time.Second)
			}
			sb.WriteString(fmt.Sprintf("%-8d %-15s %-12s %v\n",
				port.Port, port.Status.String(), service, port.Latency))
		}
		sb.WriteString("\n")
	}

	if len(data.Vulnerabilities) > 0 {
		sb.WriteString("----------------------------------------\n")
		sb.WriteString("           VULNERABILITIES              \n")
		sb.WriteString("----------------------------------------\n")
		sb.WriteString(fmt.Sprintf("%-6s %-12s %-10s %s\n", "PORT", "SERVICE", "SEVERITY", "DESCRIPTION"))
		sb.WriteString(strings.Repeat("-", 70) + "\n")

		for _, vuln := range data.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("%-6d %-12s %-10s %s\n",
				vuln.Port, vuln.Service, vuln.Severity, vuln.Description))
		}
		sb.WriteString("\n")
	}

	if len(data.FilteredPorts) > 0 {
		sb.WriteString("----------------------------------------\n")
		sb.WriteString("            FILTERED PORTS              \n")
		sb.WriteString("----------------------------------------\n")
		for i, port := range data.FilteredPorts {
			if i >= 10 {
				sb.WriteString(fmt.Sprintf("  ... and %d more filtered ports\n", len(data.FilteredPorts)-10))
				break
			}
			sb.WriteString(fmt.Sprintf("  %d/tcp\n", port.Port))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("========================================\n")
	sb.WriteString("            END OF REPORT               \n")
	sb.WriteString("========================================\n")

	return sb.String(), nil
}

func ToCSV(data ReportData) (string, error) {
	var sb strings.Builder
	writer := csv.NewWriter(&sb)

	header := []string{"port", "status", "service", "latency", "vulnerability_severity", "vulnerability_description"}
	if err := writer.Write(header); err != nil {
		return "", err
	}

	vulnMap := make(map[int]Vulnerability)
	for _, vuln := range data.Vulnerabilities {
		vulnMap[vuln.Port] = vuln
	}

	writePortRecord := func(port scanner.PortResult) error {
		service := port.Service
		if service == "" {
			service = scanner.IdentifyService(port.Port, nil, 2*time.Second)
		}

		record := []string{
			fmt.Sprintf("%d", port.Port),
			port.Status.String(),
			service,
			port.Latency.String(),
			"",
			"",
		}

		if vuln, ok := vulnMap[port.Port]; ok {
			record[4] = vuln.Severity
			record[5] = vuln.Description
		}

		return writer.Write(record)
	}

	for _, port := range data.OpenPorts {
		if err := writePortRecord(port); err != nil {
			return "", err
		}
	}

	for _, port := range data.ClosedPorts {
		if err := writePortRecord(port); err != nil {
			return "", err
		}
	}

	for _, port := range data.FilteredPorts {
		if err := writePortRecord(port); err != nil {
			return "", err
		}
	}

	writer.Flush()

	if err := writer.Error(); err != nil {
		return "", err
	}

	return sb.String(), nil
}

func GenerateSecurityScore(data ReportData) int {
	score := 100

	score -= len(data.OpenPorts) * 2

	for _, vuln := range data.Vulnerabilities {
		switch strings.ToUpper(vuln.Severity) {
		case "CRITICAL":
			score -= 25
		case "HIGH":
			score -= 15
		case "MEDIUM":
			score -= 8
		case "LOW":
			score -= 3
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}

func GetRiskLevel(score int) string {
	switch {
	case score >= 80:
		return "LOW"
	case score >= 60:
		return "MEDIUM"
	case score >= 40:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}
