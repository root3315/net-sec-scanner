package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type PortStatus int

const (
	PortOpen PortStatus = iota
	PortClosed
	PortFiltered
)

func (s PortStatus) String() string {
	switch s {
	case PortOpen:
		return "open"
	case PortClosed:
		return "closed"
	case PortFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

type PortResult struct {
	Port    int
	Status  PortStatus
	Service string
	Banner  string
	Latency time.Duration
}

type ScanResults struct {
	OpenPorts     []PortResult
	ClosedPorts   []PortResult
	FilteredPorts []PortResult
	ScanDuration  time.Duration
	TargetIP      string
}

type Config struct {
	TargetIP      string
	Ports         []int
	Timeout       time.Duration
	Concurrency   int
	Verbose       bool
	ServiceDetect bool
	MaxRetries    int
}

type NetworkScanner struct {
	config     Config
	stopped    int32
	progress   int32
	totalPorts int
}

func NewNetworkScanner(config Config) *NetworkScanner {
	if config.Concurrency <= 0 {
		config.Concurrency = 50
	}
	if config.Timeout <= 0 {
		config.Timeout = 2 * time.Second
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}

	return &NetworkScanner{
		config:     config,
		totalPorts: len(config.Ports),
	}
}

func (s *NetworkScanner) Stop() {
	atomic.StoreInt32(&s.stopped, 1)
}

func (s *NetworkScanner) IsStopped() bool {
	return atomic.LoadInt32(&s.stopped) == 1
}

func (s *NetworkScanner) Scan() (*ScanResults, error) {
	startTime := time.Now()

	results := &ScanResults{
		OpenPorts:     make([]PortResult, 0),
		ClosedPorts:   make([]PortResult, 0),
		FilteredPorts: make([]PortResult, 0),
		TargetIP:      s.config.TargetIP,
	}

	var resultsMu sync.Mutex
	var wg sync.WaitGroup

	portChan := make(chan int, s.config.Concurrency)

	for i := 0; i < s.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				if s.IsStopped() {
					return
				}

				result := s.scanPort(port)
				atomic.AddInt32(&s.progress, 1)

				resultsMu.Lock()
				switch result.Status {
				case PortOpen:
					results.OpenPorts = append(results.OpenPorts, result)
				case PortClosed:
					results.ClosedPorts = append(results.ClosedPorts, result)
				case PortFiltered:
					results.FilteredPorts = append(results.FilteredPorts, result)
				}
				resultsMu.Unlock()

				if s.config.Verbose && result.Status == PortOpen {
					if result.Service != "" && result.Service != "unknown" {
						fmt.Printf("\r[+] Port %d is %s - %s (%v)\n", port, result.Status, result.Service, result.Latency)
					} else {
						fmt.Printf("\r[+] Port %d is %s (%v)\n", port, result.Status, result.Latency)
					}
				}
			}
		}()
	}

	for _, port := range s.config.Ports {
		if s.IsStopped() {
			break
		}
		portChan <- port
	}

	close(portChan)
	wg.Wait()

	results.ScanDuration = time.Since(startTime)

	sortResults(results)

	return results, nil
}

func (s *NetworkScanner) scanPort(port int) PortResult {
	var result PortResult
	var lastErr error

	for attempt := 0; attempt < s.config.MaxRetries; attempt++ {
		if s.IsStopped() {
			return PortResult{Port: port, Status: PortFiltered}
		}

		result = s.scanPortOnce(port)
		lastErr = nil

		// If port is open or closed, no need to retry
		if result.Status == PortOpen || result.Status == PortClosed {
			return result
		}

		// Only retry on timeout (filtered)
		if result.Status == PortFiltered {
			// Small delay before retry to avoid overwhelming the network
			time.Sleep(100 * time.Millisecond)
			continue
		}
	}

	_ = lastErr
	return result
}

func (s *NetworkScanner) scanPortOnce(port int) PortResult {
	startTime := time.Now()

	address := fmt.Sprintf("%s:%d", s.config.TargetIP, port)
	conn, err := net.DialTimeout("tcp", address, s.config.Timeout)
	latency := time.Since(startTime)

	result := PortResult{
		Port:    port,
		Latency: latency,
	}

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.Status = PortFiltered
		} else {
			result.Status = PortClosed
		}
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(s.config.Timeout))

	result.Status = PortOpen

	if s.config.ServiceDetect {
		service, banner := s.detectServiceWithBanner(conn, port)
		result.Service = service
		result.Banner = banner
	} else {
		result.Service = IdentifyService(port, conn, s.config.Timeout)
	}

	return result
}

func (s *NetworkScanner) detectServiceWithBanner(conn net.Conn, port int) (string, string) {
	grabber := NewBannerGrabber(conn, s.config.Timeout)

	banner, err := grabber.Grab()
	if err != nil {
		probe := getProtocolProbe(port)
		if len(probe) > 0 {
			banner, err = grabber.GrabWithProbe(probe)
			if err != nil {
				service := IdentifyService(port, nil, s.config.Timeout)
				return service, ""
			}
		} else {
			service := IdentifyService(port, nil, s.config.Timeout)
			return service, ""
		}
	}

	banner = truncateBanner(banner)
	service := matchServiceFromBanner(banner, port)

	if service == "unknown" {
		service = IdentifyService(port, nil, s.config.Timeout)
	}

	return service, banner
}

func (s *NetworkScanner) GetProgress() (int, int) {
	return int(atomic.LoadInt32(&s.progress)), s.totalPorts
}

func sortResults(results *ScanResults) {
	sortByPort := func(ports []PortResult) {
		sort.Slice(ports, func(i, j int) bool {
			return ports[i].Port < ports[j].Port
		})
	}

	sortByPort(results.OpenPorts)
	sortByPort(results.ClosedPorts)
	sortByPort(results.FilteredPorts)
}

func QuickScan(host string, ports []int, timeout time.Duration) (*ScanResults, error) {
	config := Config{
		TargetIP:    host,
		Ports:       ports,
		Timeout:     timeout,
		Concurrency: 100,
		Verbose:     false,
		MaxRetries:  3,
	}

	scanner := NewNetworkScanner(config)
	return scanner.Scan()
}

func ScanCommonPorts(host string, timeout time.Duration) (*ScanResults, error) {
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 443, 445, 993, 995, 1723, 3306, 3389,
		5900, 8080, 8443,
	}

	return QuickScan(host, commonPorts, timeout)
}
