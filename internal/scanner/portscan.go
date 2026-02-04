package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nullblocks-systems/domrecon/internal/types"
)

// PortScanner scans for open ports on hosts
type PortScanner struct {
	ports       []int
	timeout     time.Duration
	concurrency int
}

// NewPortScanner creates a new port scanner
func NewPortScanner(ports []int, concurrency int) *PortScanner {
	return &PortScanner{
		ports:       ports,
		timeout:     1 * time.Second,
		concurrency: concurrency * 5, // Increase concurrency for port scanning
	}
}

// Scan scans the given hosts for open ports
func (s *PortScanner) Scan(ctx context.Context, hosts []string) ([]types.PortResult, error) {
	var (
		mu      sync.Mutex
		results []types.PortResult
		wg      sync.WaitGroup
		sem     = make(chan struct{}, s.concurrency)
	)

	type scanTarget struct {
		host string
		port int
	}

	// Generate all host:port combinations
	var targets []scanTarget
	for _, host := range hosts {
		for _, port := range s.ports {
			targets = append(targets, scanTarget{host, port})
		}
	}

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(t scanTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			if s.isPortOpen(ctx, t.host, t.port) {
				service := guessService(t.port)
				mu.Lock()
				results = append(results, types.PortResult{
					Host:    t.host,
					Port:    t.port,
					Service: service,
					State:   "open",
				})
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	return results, nil
}

// isPortOpen checks if a port is open using TCP connect
func (s *PortScanner) isPortOpen(ctx context.Context, host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)

	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// guessService returns a likely service name for common ports
func guessService(port int) string {
	services := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		4502:  "silverlight",
		4503:  "silverlight",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		7000:  "cassandra",
		7001:  "weblogic",
		7002:  "weblogic",
		7777:  "cbt",
		8000:  "http-alt",
		8080:  "http-proxy",
		8443:  "https-alt",
		8888:  "http-alt",
		9200:  "elasticsearch",
		9300:  "elasticsearch",
		27017: "mongodb",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}

// ParsePorts converts a slice of port strings to integers
func ParsePorts(portStrings []string) ([]int, error) {
	var ports []int
	for _, ps := range portStrings {
		var port int
		if _, err := fmt.Sscanf(ps, "%d", &port); err != nil {
			return nil, fmt.Errorf("invalid port: %s", ps)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port out of range: %d", port)
		}
		ports = append(ports, port)
	}
	return ports, nil
}
