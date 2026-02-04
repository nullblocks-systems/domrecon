package scanner

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/nullblocks-systems/domrecon/internal/types"
)

// VulnScanner performs vulnerability scanning using nuclei-like templates
type VulnScanner struct {
	templatesPath string
	concurrency   int
}

// NewVulnScanner creates a new vulnerability scanner
func NewVulnScanner(templatesPath string, concurrency int) *VulnScanner {
	return &VulnScanner{
		templatesPath: templatesPath,
		concurrency:   concurrency,
	}
}

// Scan performs vulnerability scanning on the given URLs
// Note: This is a simplified implementation. For full nuclei functionality,
// you would integrate with projectdiscovery/nuclei as a library.
func (s *VulnScanner) Scan(ctx context.Context, hosts []types.LiveHost) ([]types.VulnResult, error) {
	var (
		mu      sync.Mutex
		results []types.VulnResult
		wg      sync.WaitGroup
		sem     = make(chan struct{}, s.concurrency)
	)

	for _, host := range hosts {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(h types.LiveHost) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := s.checkHost(ctx, h)
			if len(vulns) > 0 {
				mu.Lock()
				results = append(results, vulns...)
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	return results, nil
}

// checkHost performs basic vulnerability checks on a host
func (s *VulnScanner) checkHost(ctx context.Context, host types.LiveHost) []types.VulnResult {
	var vulns []types.VulnResult

	// Check for information disclosure in headers
	vulns = append(vulns, s.checkHeaderVulns(host)...)

	return vulns
}

// checkHeaderVulns checks for vulnerabilities in HTTP headers
func (s *VulnScanner) checkHeaderVulns(host types.LiveHost) []types.VulnResult {
	var vulns []types.VulnResult

	// Check for server version disclosure
	if server, ok := host.Headers["Server"]; ok {
		if containsVersion(server) {
			vulns = append(vulns, types.VulnResult{
				Template:    "http-server-header",
				Name:        "Server Version Disclosure",
				Severity:    "info",
				Host:        host.URL,
				MatchedAt:   host.URL,
				Description: "Server header discloses version: " + server,
				Tags:        []string{"exposure", "headers"},
			})
		}
	}

	// Check for X-Powered-By disclosure
	if powered, ok := host.Headers["X-Powered-By"]; ok {
		vulns = append(vulns, types.VulnResult{
			Template:    "x-powered-by-header",
			Name:        "Technology Stack Disclosure",
			Severity:    "info",
			Host:        host.URL,
			MatchedAt:   host.URL,
			Description: "X-Powered-By header discloses: " + powered,
			Tags:        []string{"exposure", "headers"},
		})
	}

	// Check for missing security headers
	securityHeaders := map[string]string{
		"Strict-Transport-Security": "Missing HSTS Header",
		"Content-Security-Policy":   "Missing CSP Header",
		"X-Frame-Options":           "Missing X-Frame-Options Header",
		"X-Content-Type-Options":    "Missing X-Content-Type-Options Header",
	}

	for header, name := range securityHeaders {
		if _, ok := host.Headers[header]; !ok {
			vulns = append(vulns, types.VulnResult{
				Template:    "missing-" + strings.ToLower(header),
				Name:        name,
				Severity:    "low",
				Host:        host.URL,
				MatchedAt:   host.URL,
				Description: "Security header " + header + " is not set",
				Tags:        []string{"misconfig", "headers"},
			})
		}
	}

	return vulns
}

// containsVersion checks if a string contains version information
func containsVersion(s string) bool {
	versionPattern := regexp.MustCompile(`\d+\.\d+`)
	return versionPattern.MatchString(s)
}
