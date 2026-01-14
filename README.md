# net-sec-scanner

A fast network security scanner CLI written in Go for vulnerability assessment and port scanning.

## Features

- **TCP Port Scanning**: Fast concurrent port scanning with configurable timeout
- **Service Detection**: Identifies services running on open ports
- **Vulnerability Checking**: Basic vulnerability assessment for common services
- **Multiple Output Formats**: Text, JSON, and CSV report generation
- **Flexible Port Selection**: Scan specific ports, port ranges, or common ports
- **Progress Tracking**: Real-time scan progress with verbose mode
- **Signal Handling**: Graceful shutdown on interrupt signals

## Installation

### From Source

```bash
git clone https://github.com/yourusername/net-sec-scanner.git
cd net-sec-scanner
go build -o net-sec-scanner .
```

### Using Go Install

```bash
go install github.com/yourusername/net-sec-scanner@latest
```

### Prerequisites

- Go 1.21 or later
- Network access to target hosts

## Usage

### Basic Scan

Scan common ports (1-1024) on a target:

```bash
./net-sec-scanner -host 192.168.1.1
```

### Specific Ports

Scan specific ports:

```bash
./net-sec-scanner -host 192.168.1.1 -ports 22,80,443,8080
```

### Port Range

Scan a range of ports:

```bash
./net-sec-scanner -host 192.168.1.1 -range 1-1000
```

### Service Detection

Enable service detection on open ports:

```bash
./net-sec-scanner -host 192.168.1.1 -service-detect
```

### Vulnerability Check

Check for known vulnerabilities:

```bash
./net-sec-scanner -host 192.168.1.1 -vuln-check
```

### Output Formats

Generate JSON report:

```bash
./net-sec-scanner -host 192.168.1.1 -format json -output report.json
```

Generate CSV report:

```bash
./net-sec-scanner -host 192.168.1.1 -format csv -output report.csv
```

### Verbose Mode

Enable verbose output:

```bash
./net-sec-scanner -host 192.168.1.1 -verbose
```

### Full Example

```bash
./net-sec-scanner -host example.com -range 1-1024 -service-detect -vuln-check -format json -output scan_results.json -verbose
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-host` | Target host IP address or hostname (required) | - |
| `-ports` | Comma-separated list of ports to scan | - |
| `-range` | Port range to scan (e.g., 1-1000) | 1-1024 |
| `-timeout` | Connection timeout in seconds | 2 |
| `-concurrency` | Number of concurrent connections | 50 |
| `-format` | Output format: text, json, csv | text |
| `-output` | Output file path (default: stdout) | stdout |
| `-verbose` | Enable verbose output | false |
| `-service-detect` | Detect services on open ports | false |
| `-vuln-check` | Check for known vulnerabilities | false |
| `-version` | Show version information | false |

## How It Works

### Port Scanning

The scanner uses TCP connect scanning to determine port status:

1. **Open**: TCP connection successful
2. **Closed**: Connection refused (RST packet received)
3. **Filtered**: Connection timeout (no response)

### Service Detection

Service detection works by:

1. Checking well-known port assignments (IANA)
2. Attempting banner grabbing on open ports
3. Pattern matching against known service signatures

### Vulnerability Assessment

The vulnerability checker identifies common security issues:

- Cleartext protocols (FTP, Telnet, POP3)
- Exposed database ports (MySQL, PostgreSQL, MongoDB, Redis)
- Potentially vulnerable services (SMB, NetBIOS)

## Project Structure

```
net-sec-scanner/
├── main.go              # Main entry point and CLI handling
├── go.mod               # Go module definition
├── go.sum               # Dependency checksums
├── scanner/
│   ├── scanner.go       # Core scanning logic
│   └── port.go          # Port utilities and service detection
├── report/
│   └── report.go        # Report generation (text, JSON, CSV)
├── tests/
│   └── scanner_test.go  # Unit tests
└── README.md            # Documentation
```

## Running Tests

```bash
go test ./... -v
```

## Examples

### Scan a Web Server

```bash
$ ./net-sec-scanner -host scanme.nmap.org -ports 22,80,443 -service-detect

========================================
     NETWORK SECURITY SCAN REPORT      
========================================

Target:      scanme.nmap.org (45.33.32.156)
Scan Time:   2024-01-15 10:30:45

----------------------------------------
                 SUMMARY                
----------------------------------------
Open Ports:      2
Closed Ports:    1
Filtered Ports:  0
Vulnerabilities: 0

----------------------------------------
              OPEN PORTS                
----------------------------------------
PORT     STATUS          SERVICE      LATENCY
-------------------------------------------------------
22       open            ssh          45ms
80       open            http         52ms
```

### JSON Output

```bash
$ ./net-sec-scanner -host 192.168.1.1 -ports 22,80 -format json

{
  "target": "192.168.1.1",
  "target_ip": "192.168.1.1",
  "scan_time": "2024-01-15T10:30:45Z",
  "open_ports": [
    {"port": 22, "status": "open", "service": "ssh", "latency": "45ms"},
    {"port": 80, "status": "open", "service": "http", "latency": "52ms"}
  ],
  "summary": {
    "total_open": 2,
    "total_closed": 0,
    "total_filtered": 0
  }
}
```

## Security Considerations

- Only scan systems you own or have explicit permission to scan
- Unauthorized scanning may violate laws and terms of service
- Use responsibly and ethically

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Support

For issues and feature requests, please open an issue on the GitHub repository.
