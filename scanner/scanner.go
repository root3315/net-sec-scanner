package scanner

import (
	"fmt"
	"net"
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
	TargetIP    string
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	Verbose     bool
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
					fmt.Printf("\r[+] Port %d is %s (%v)\n", port, result.Status, result.Latency)
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

	conn.Close()
	result.Status = PortOpen
	result.Service = IdentifyService(port, conn)

	return result
}

func (s *NetworkScanner) GetProgress() (int, int) {
	return int(atomic.LoadInt32(&s.progress)), s.totalPorts
}

func sortResults(results *ScanResults) {
	sortByPort := func(ports []PortResult) {
		for i := 0; i < len(ports)-1; i++ {
			for j := i + 1; j < len(ports); j++ {
				if ports[i].Port > ports[j].Port {
					ports[i], ports[j] = ports[j], ports[i]
				}
			}
		}
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
