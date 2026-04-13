package tests

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"net-sec-scanner/report"
	"net-sec-scanner/scanner"
)

func TestIdentifyService(t *testing.T) {
	tests := []struct {
		name string
		port int
		want string
	}{
		{
			name: "SSH port",
			port: 22,
			want: "ssh",
		},
		{
			name: "HTTP port",
			port: 80,
			want: "http",
		},
		{
			name: "HTTPS port",
			port: 443,
			want: "https",
		},
		{
			name: "MySQL port",
			port: 3306,
			want: "mysql",
		},
		{
			name: "unknown port",
			port: 12345,
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanner.IdentifyService(tt.port, nil, 0)
			if got != tt.want {
				t.Errorf("IdentifyService(%d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

func TestGetServiceName(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{21, "ftp"},
		{22, "ssh"},
		{25, "smtp"},
		{53, "domain"},
		{80, "http"},
		{443, "https"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := scanner.GetServiceName(tt.port)
			if got != tt.want {
				t.Errorf("GetServiceName(%d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

func TestIsCommonPort(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{22, true},
		{80, true},
		{443, true},
		{31337, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := scanner.IsCommonPort(tt.port)
			if got != tt.want {
				t.Errorf("IsCommonPort(%d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

func TestPortStatusString(t *testing.T) {
	tests := []struct {
		status scanner.PortStatus
		want   string
	}{
		{scanner.PortOpen, "open"},
		{scanner.PortClosed, "closed"},
		{scanner.PortFiltered, "filtered"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.want {
				t.Errorf("PortStatus(%d).String() = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestNetworkScannerStop(t *testing.T) {
	config := scanner.Config{
		TargetIP:    "127.0.0.1",
		Ports:       []int{80, 443},
		Timeout:     1 * time.Second,
		Concurrency: 10,
		Verbose:     false,
	}

	s := scanner.NewNetworkScanner(config)

	if s.IsStopped() {
		t.Error("Scanner should not be stopped initially")
	}

	s.Stop()

	if !s.IsStopped() {
		t.Error("Scanner should be stopped after Stop()")
	}
}

func TestNetworkScannerScan(t *testing.T) {
	config := scanner.Config{
		TargetIP:    "127.0.0.1",
		Ports:       []int{1, 2, 3},
		Timeout:     100 * time.Millisecond,
		Concurrency: 5,
		Verbose:     false,
	}

	s := scanner.NewNetworkScanner(config)
	results, err := s.Scan()

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	if results == nil {
		t.Error("Scan() returned nil results")
		return
	}

	totalPorts := len(results.OpenPorts) + len(results.ClosedPorts) + len(results.FilteredPorts)
	if totalPorts != 3 {
		t.Errorf("Scan() scanned %d ports, want 3", totalPorts)
	}
}

func TestQuickScan(t *testing.T) {
	ports := []int{80, 443, 8080}
	results, err := scanner.QuickScan("127.0.0.1", ports, 100*time.Millisecond)

	if err != nil {
		t.Errorf("QuickScan() error = %v", err)
		return
	}

	if results == nil {
		t.Error("QuickScan() returned nil results")
	}
}

func TestScanCommonPorts(t *testing.T) {
	results, err := scanner.ScanCommonPorts("127.0.0.1", 100*time.Millisecond)

	if err != nil {
		t.Errorf("ScanCommonPorts() error = %v", err)
		return
	}

	if results == nil {
		t.Error("ScanCommonPorts() returned nil results")
	}
}

func TestReportToJSON(t *testing.T) {
	data := report.ReportData{
		Target:   "test.example.com",
		TargetIP: "192.168.1.1",
		ScanTime: time.Now(),
		OpenPorts: []scanner.PortResult{
			{Port: 22, Status: scanner.PortOpen, Service: "ssh", Latency: 10 * time.Millisecond},
			{Port: 80, Status: scanner.PortOpen, Service: "http", Latency: 15 * time.Millisecond},
		},
		Vulnerabilities: []report.Vulnerability{
			{Port: 22, Service: "ssh", Severity: "MEDIUM", Description: "SSH version outdated"},
		},
	}

	jsonStr, err := report.ToJSON(data)
	if err != nil {
		t.Errorf("ToJSON() error = %v", err)
		return
	}

	var reportJSON report.JSONReport
	err = json.Unmarshal([]byte(jsonStr), &reportJSON)
	if err != nil {
		t.Errorf("ToJSON() produced invalid JSON: %v", err)
		return
	}

	if reportJSON.Target != data.Target {
		t.Errorf("ToJSON() target = %v, want %v", reportJSON.Target, data.Target)
	}

	if len(reportJSON.OpenPorts) != len(data.OpenPorts) {
		t.Errorf("ToJSON() open ports = %d, want %d", len(reportJSON.OpenPorts), len(data.OpenPorts))
	}
}

func TestReportToText(t *testing.T) {
	data := report.ReportData{
		Target:   "test.example.com",
		TargetIP: "192.168.1.1",
		ScanTime: time.Now(),
		OpenPorts: []scanner.PortResult{
			{Port: 22, Status: scanner.PortOpen, Service: "ssh", Latency: 10 * time.Millisecond},
		},
	}

	textStr, err := report.ToText(data)
	if err != nil {
		t.Errorf("ToText() error = %v", err)
		return
	}

	if !strings.Contains(textStr, "test.example.com") {
		t.Error("ToText() output missing target")
	}

	if !strings.Contains(textStr, "192.168.1.1") {
		t.Error("ToText() output missing target IP")
	}

	if !strings.Contains(textStr, "OPEN PORTS") {
		t.Error("ToText() output missing open ports section")
	}
}

func TestReportToCSV(t *testing.T) {
	data := report.ReportData{
		Target:   "test.example.com",
		TargetIP: "192.168.1.1",
		ScanTime: time.Now(),
		OpenPorts: []scanner.PortResult{
			{Port: 22, Status: scanner.PortOpen, Service: "ssh", Latency: 10 * time.Millisecond},
			{Port: 80, Status: scanner.PortOpen, Service: "http", Latency: 15 * time.Millisecond},
		},
	}

	csvStr, err := report.ToCSV(data)
	if err != nil {
		t.Errorf("ToCSV() error = %v", err)
		return
	}

	if !strings.Contains(csvStr, "port,status,service") {
		t.Error("ToCSV() output missing header")
	}

	if !strings.Contains(csvStr, "22,open,ssh") {
		t.Error("ToCSV() output missing port 22")
	}
}

func TestGenerateSecurityScore(t *testing.T) {
	tests := []struct {
		name          string
		openPorts     int
		vulnerabilities []report.Vulnerability
		wantMaxScore  int
		wantMinScore  int
	}{
		{
			name:         "no issues",
			openPorts:    0,
			wantMaxScore: 100,
			wantMinScore: 100,
		},
		{
			name:         "few open ports",
			openPorts:    5,
			wantMaxScore: 90,
			wantMinScore: 80,
		},
		{
			name:      "with critical vuln",
			openPorts: 2,
			vulnerabilities: []report.Vulnerability{
				{Port: 23, Service: "telnet", Severity: "CRITICAL", Description: "cleartext"},
			},
			wantMaxScore: 80,
			wantMinScore: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := report.ReportData{
				OpenPorts:       make([]scanner.PortResult, tt.openPorts),
				Vulnerabilities: tt.vulnerabilities,
			}

			score := report.GenerateSecurityScore(data)

			if score > tt.wantMaxScore {
				t.Errorf("GenerateSecurityScore() = %d, want <= %d", score, tt.wantMaxScore)
			}
			if score < tt.wantMinScore {
				t.Errorf("GenerateSecurityScore() = %d, want >= %d", score, tt.wantMinScore)
			}
		})
	}
}

func TestGetRiskLevel(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{90, "LOW"},
		{80, "LOW"},
		{70, "MEDIUM"},
		{50, "HIGH"},
		{30, "CRITICAL"},
		{0, "CRITICAL"},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := report.GetRiskLevel(tt.score)
			if got != tt.want {
				t.Errorf("GetRiskLevel(%d) = %v, want %v", tt.score, got, tt.want)
			}
		})
	}
}

func TestGetPortByService(t *testing.T) {
	ports := scanner.GetPortByService("ssh")
	if len(ports) == 0 {
		t.Error("GetPortByService('ssh') returned no ports")
	}

	found := false
	for _, p := range ports {
		if p == 22 {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetPortByService('ssh') did not return port 22")
	}
}

func TestGetCommonPorts(t *testing.T) {
	ports := scanner.GetCommonPorts()
	if len(ports) == 0 {
		t.Error("GetCommonPorts() returned no ports")
	}
}

func TestBannerGrabber(t *testing.T) {
	mockConn := &mockConn{
		readData: []byte("SSH-2.0-OpenSSH_8.0\r\n"),
	}

	grabber := scanner.NewBannerGrabber(mockConn, 1*time.Second)
	banner, err := grabber.Grab()

	if err != nil {
		t.Errorf("Grab() error = %v", err)
		return
	}

	if !strings.Contains(banner, "SSH") {
		t.Errorf("Grab() banner = %v, want SSH", banner)
	}
}

func TestBannerGrabberWithProbe(t *testing.T) {
	mockConn := &mockConn{
		readData: []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"),
	}

	grabber := scanner.NewBannerGrabber(mockConn, 1*time.Second)
	probe := []byte("GET / HTTP/1.0\r\n\r\n")
	banner, err := grabber.GrabWithProbe(probe)

	if err != nil {
		t.Errorf("GrabWithProbe() error = %v", err)
		return
	}

	if !strings.Contains(banner, "HTTP") {
		t.Errorf("GrabWithProbe() banner = %v, want HTTP", banner)
	}
}

func TestMatchServiceFromBanner(t *testing.T) {
	tests := []struct {
		name    string
		banner  string
		port    int
		want    string
	}{
		{
			name:   "SSH banner",
			banner: "SSH-2.0-OpenSSH_8.0",
			port:   22,
			want:   "ssh",
		},
		{
			name:   "FTP banner",
			banner: "220 vsftpd 3.0.3",
			port:   21,
			want:   "ftp",
		},
		{
			name:   "HTTP nginx",
			banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
			port:   80,
			want:   "http",
		},
		{
			name:   "HTTP apache",
			banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41",
			port:   80,
			want:   "http",
		},
		{
			name:   "SMTP banner",
			banner: "220 mail.example.com ESMTP Postfix",
			port:   25,
			want:   "smtp",
		},
		{
			name:   "MySQL banner",
			banner: "5.7.32-0ubuntu0.18.04.1",
			port:   3306,
			want:   "mysql",
		},
		{
			name:   "Redis banner",
			banner: "REDIS",
			port:   6379,
			want:   "redis",
		},
		{
			name:   "Elasticsearch banner",
			banner: "Elasticsearch/7.10.0",
			port:   9200,
			want:   "elasticsearch",
		},
		{
			name:   "MongoDB banner",
			banner: "MongoDB",
			port:   27017,
			want:   "mongodb",
		},
		{
			name:   "Unknown banner",
			banner: "Some unknown service",
			port:   12345,
			want:   "unknown",
		},
		{
			name:   "Empty banner",
			banner: "",
			port:   80,
			want:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanner.MatchServiceFromBanner(tt.banner, tt.port)
			if got != tt.want {
				t.Errorf("MatchServiceFromBanner(%q, %d) = %v, want %v", tt.banner, tt.port, got, tt.want)
			}
		})
	}
}

func TestGetProtocolProbe(t *testing.T) {
	tests := []struct {
		port     int
		wantNil  bool
		wantLen  int
	}{
		{80, false, 30},
		{443, false, 30},
		{21, false, 6},
		{22, false, 2},
		{3306, false, 39},
		{5432, false, 8},
		{6379, false, 6},
		{99999, true, 0},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("port_%d", tt.port), func(t *testing.T) {
			probe := scanner.GetProtocolProbe(tt.port)
			if tt.wantNil && probe != nil {
				t.Errorf("GetProtocolProbe(%d) = %v, want nil", tt.port, probe)
			}
			if !tt.wantNil && probe == nil {
				t.Errorf("GetProtocolProbe(%d) = nil, want probe", tt.port)
			}
			if !tt.wantNil && len(probe) != tt.wantLen {
				t.Errorf("GetProtocolProbe(%d) len = %d, want %d", tt.port, len(probe), tt.wantLen)
			}
		})
	}
}

func TestTruncateBanner(t *testing.T) {
	shortBanner := "SSH-2.0-OpenSSH_8.0"
	longBanner := strings.Repeat("A", 300)

	truncated := scanner.TruncateBanner(shortBanner)
	if truncated != shortBanner {
		t.Errorf("TruncateBanner(short) = %v, want %v", truncated, shortBanner)
	}

	truncated = scanner.TruncateBanner(longBanner)
	if len(truncated) > 203 {
		t.Errorf("TruncateBanner(long) len = %d, want <= 203", len(truncated))
	}
	if !strings.HasSuffix(truncated, "...") {
		t.Errorf("TruncateBanner(long) missing ... suffix")
	}
}

func TestGetServiceBanner(t *testing.T) {
	mockConn := &mockConn{
		readData: []byte("Test Banner"),
	}

	banner, err := scanner.GetServiceBanner(mockConn, 1*time.Second)
	if err != nil {
		t.Errorf("GetServiceBanner() error = %v", err)
		return
	}

	if banner != "Test Banner" {
		t.Errorf("GetServiceBanner() = %v, want Test Banner", banner)
	}
}

func TestGetServiceBannerNilConn(t *testing.T) {
	_, err := scanner.GetServiceBanner(nil, 1*time.Second)
	if err == nil {
		t.Error("GetServiceBanner(nil) error = nil, want error")
	}
}

func TestBannerGrabberNilConn(t *testing.T) {
	grabber := scanner.NewBannerGrabber(nil, 1*time.Second)
	_, err := grabber.Grab()
	if err == nil {
		t.Error("BannerGrabber.Grab() with nil conn error = nil, want error")
	}
}

func TestBannerGrabberNilConnWithProbe(t *testing.T) {
	grabber := scanner.NewBannerGrabber(nil, 1*time.Second)
	_, err := grabber.GrabWithProbe([]byte("probe"))
	if err == nil {
		t.Error("BannerGrabber.GrabWithProbe() with nil conn error = nil, want error")
	}
}

type mockConn struct {
	readData []byte
	writeData []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if len(m.readData) == 0 {
		return 0, fmt.Errorf("no data")
	}
	n = copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return nil
}

func (m *mockConn) RemoteAddr() net.Addr {
	return nil
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestPortResult(t *testing.T) {
	result := scanner.PortResult{
		Port:    80,
		Status:  scanner.PortOpen,
		Service: "http",
		Latency: 50 * time.Millisecond,
	}

	if result.Port != 80 {
		t.Errorf("PortResult.Port = %d, want 80", result.Port)
	}

	if result.Status != scanner.PortOpen {
		t.Errorf("PortResult.Status = %v, want PortOpen", result.Status)
	}

	if result.Service != "http" {
		t.Errorf("PortResult.Service = %v, want http", result.Service)
	}
}

func TestScanResults(t *testing.T) {
	results := scanner.ScanResults{
		OpenPorts: []scanner.PortResult{
			{Port: 22, Status: scanner.PortOpen},
			{Port: 80, Status: scanner.PortOpen},
		},
		ClosedPorts: []scanner.PortResult{
			{Port: 23, Status: scanner.PortClosed},
		},
		ScanDuration: 5 * time.Second,
		TargetIP:     "192.168.1.1",
	}

	if len(results.OpenPorts) != 2 {
		t.Errorf("ScanResults.OpenPorts length = %d, want 2", len(results.OpenPorts))
	}

	if len(results.ClosedPorts) != 1 {
		t.Errorf("ScanResults.ClosedPorts length = %d, want 1", len(results.ClosedPorts))
	}
}

func TestNetworkScannerConfig(t *testing.T) {
	config := scanner.Config{
		TargetIP:    "10.0.0.1",
		Ports:       []int{22, 80, 443},
		Timeout:     5 * time.Second,
		Concurrency: 100,
		Verbose:     true,
	}

	s := scanner.NewNetworkScanner(config)
	if s == nil {
		t.Error("NewNetworkScanner() returned nil")
	}
}

func TestDefaultConcurrency(t *testing.T) {
	config := scanner.Config{
		TargetIP:    "127.0.0.1",
		Ports:       []int{80},
		Concurrency: 0,
	}

	s := scanner.NewNetworkScanner(config)
	if s == nil {
		t.Error("NewNetworkScanner() with zero concurrency returned nil")
	}
}

func TestDefaultTimeout(t *testing.T) {
	config := scanner.Config{
		TargetIP: "127.0.0.1",
		Ports:    []int{80},
		Timeout:  0,
	}

	s := scanner.NewNetworkScanner(config)
	if s == nil {
		t.Error("NewNetworkScanner() with zero timeout returned nil")
	}
}

func TestResolveHost(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	if ip == nil {
		t.Error("Failed to parse 127.0.0.1")
	}

	_, err := net.LookupIP("localhost")
	if err != nil {
		t.Skip("Cannot resolve localhost, skipping DNS resolution test")
	}
}

func TestVulnerabilityStruct(t *testing.T) {
	vuln := report.Vulnerability{
		Port:        23,
		Service:     "telnet",
		Severity:    "CRITICAL",
		Description: "Telnet transmits data in cleartext",
	}

	if vuln.Port != 23 {
		t.Errorf("Vulnerability.Port = %d, want 23", vuln.Port)
	}

	if vuln.Severity != "CRITICAL" {
		t.Errorf("Vulnerability.Severity = %v, want CRITICAL", vuln.Severity)
	}
}

func TestJSONReportStruct(t *testing.T) {
	jsonReport := report.JSONReport{
		Target:   "example.com",
		TargetIP: "93.184.216.34",
		ScanTime: time.Now().Format(time.RFC3339),
		Summary: report.Summary{
			TotalOpen:     5,
			TotalClosed:   100,
			TotalFiltered: 10,
			TotalVulns:    2,
			CriticalVulns: 1,
			HighVulns:     1,
			MediumVulns:   0,
		},
	}

	if jsonReport.Summary.TotalOpen != 5 {
		t.Errorf("JSONReport.Summary.TotalOpen = %d, want 5", jsonReport.Summary.TotalOpen)
	}
}
