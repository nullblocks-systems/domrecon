package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nullblocks-systems/domrecon/internal/types"
)

// SubdomainFinder discovers subdomains for a given domain
type SubdomainFinder struct {
	client      *http.Client
	concurrency int
}

// NewSubdomainFinder creates a new subdomain finder
func NewSubdomainFinder(concurrency int) *SubdomainFinder {
	return &SubdomainFinder{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		concurrency: concurrency,
	}
}

// Find discovers subdomains using multiple sources
func (f *SubdomainFinder) Find(ctx context.Context, domain string) ([]types.Subdomain, error) {
	var (
		mu         sync.Mutex
		subdomains = make(map[string]string) // domain -> source
		wg         sync.WaitGroup
	)

	// Add the root domain
	subdomains[domain] = "input"

	// Create a timeout context for subdomain discovery (max 3 seconds)
	discoverCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	sources := []struct {
		name string
		fn   func(context.Context, string) ([]string, error)
	}{
		{"crt.sh", f.crtsh},
		{"hackertarget", f.hackertarget},
		{"threatcrowd", f.threatcrowd},
		{"urlscan", f.urlscan},
		{"otx", f.otx},
	}

	for _, src := range sources {
		wg.Add(1)
		go func(name string, fn func(context.Context, string) ([]string, error)) {
			defer wg.Done()

			results, err := fn(discoverCtx, domain)
			if err != nil {
				return // silently skip failed sources
			}

			mu.Lock()
			for _, sub := range results {
				sub = cleanDomain(sub)
				if isValidSubdomain(sub, domain) {
					if _, exists := subdomains[sub]; !exists {
						subdomains[sub] = name
					}
				}
			}
			mu.Unlock()
		}(src.name, src.fn)
	}

	wg.Wait()

	result := make([]types.Subdomain, 0, len(subdomains))
	for name, source := range subdomains {
		result = append(result, types.Subdomain{
			Name:   name,
			Source: source,
		})
	}

	return result, nil
}

// crt.sh - Certificate Transparency logs
func (f *SubdomainFinder) crtsh(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Extract domains from JSON response using regex (simpler than full JSON parse)
	re := regexp.MustCompile(`"name_value"\s*:\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	var results []string
	for _, m := range matches {
		if len(m) > 1 {
			// Handle wildcard and multi-line entries
			for _, d := range strings.Split(m[1], "\\n") {
				d = strings.TrimPrefix(d, "*.")
				results = append(results, d)
			}
		}
	}

	return results, nil
}

// hackertarget API
func (f *SubdomainFinder) hackertarget(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) > 0 && parts[0] != "" {
			results = append(results, parts[0])
		}
	}

	return results, nil
}

// threatcrowd API
func (f *SubdomainFinder) threatcrowd(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Extract subdomains from JSON
	re := regexp.MustCompile(`"subdomains"\s*:\s*\[([^\]]+)\]`)
	match := re.FindStringSubmatch(string(body))
	if len(match) < 2 {
		return nil, nil
	}

	subRe := regexp.MustCompile(`"([^"]+)"`)
	subMatches := subRe.FindAllStringSubmatch(match[1], -1)

	var results []string
	for _, m := range subMatches {
		if len(m) > 1 {
			results = append(results, m[1])
		}
	}

	return results, nil
}

// urlscan.io API
func (f *SubdomainFinder) urlscan(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Extract domains from response
	re := regexp.MustCompile(`"domain"\s*:\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	var results []string
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			results = append(results, m[1])
		}
	}

	return results, nil
}

// AlienVault OTX API
func (f *SubdomainFinder) otx(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Extract hostnames from response
	re := regexp.MustCompile(`"hostname"\s*:\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	var results []string
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			results = append(results, m[1])
		}
	}

	return results, nil
}

// cleanDomain normalizes a domain name
func cleanDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}

// isValidSubdomain checks if a subdomain belongs to the target domain
func isValidSubdomain(subdomain, domain string) bool {
	if subdomain == "" {
		return false
	}
	return subdomain == domain || strings.HasSuffix(subdomain, "."+domain)
}
