package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nullblocks-systems/domrecon/internal/types"
)

// HTTPProber probes hosts for HTTP/HTTPS services
type HTTPProber struct {
	client      *http.Client
	concurrency int
}

// NewHTTPProber creates a new HTTP prober
func NewHTTPProber(concurrency int) *HTTPProber {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 2 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       10 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		DisableKeepAlives:     true,
	}

	return &HTTPProber{
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		concurrency: concurrency,
	}
}

// Probe checks which hosts respond to HTTP/HTTPS
func (p *HTTPProber) Probe(ctx context.Context, subdomains []types.Subdomain) ([]types.LiveHost, error) {
	var (
		mu      sync.Mutex
		results []types.LiveHost
		wg      sync.WaitGroup
		sem     = make(chan struct{}, p.concurrency)
	)

	// Generate URLs to probe (both HTTP and HTTPS)
	type probeTarget struct {
		subdomain string
		url       string
	}

	var targets []probeTarget
	for _, sub := range subdomains {
		targets = append(targets,
			probeTarget{sub.Name, fmt.Sprintf("https://%s", sub.Name)},
			probeTarget{sub.Name, fmt.Sprintf("http://%s", sub.Name)},
		)
	}

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(t probeTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			host, err := p.probeURL(ctx, t.url)
			if err != nil {
				return
			}

			mu.Lock()
			results = append(results, *host)
			mu.Unlock()
		}(target)
	}

	wg.Wait()

	// Deduplicate - prefer HTTPS over HTTP
	return deduplicateHosts(results), nil
}

func (p *HTTPProber) probeURL(ctx context.Context, url string) (*types.LiveHost, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; domrecon/1.0)")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read body (limited to 1MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	// Extract title
	title := extractTitle(string(body))

	// Extract headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	return &types.LiveHost{
		URL:        url,
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Title:      title,
		BodySize:   len(body),
	}, nil
}

// extractTitle extracts the title from HTML content
func extractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	match := re.FindStringSubmatch(body)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

// deduplicateHosts removes duplicate hosts, preferring HTTPS
func deduplicateHosts(hosts []types.LiveHost) []types.LiveHost {
	seen := make(map[string]types.LiveHost)

	for _, h := range hosts {
		// Extract hostname from URL
		hostname := strings.TrimPrefix(h.URL, "https://")
		hostname = strings.TrimPrefix(hostname, "http://")

		existing, exists := seen[hostname]
		if !exists {
			seen[hostname] = h
		} else {
			// Prefer HTTPS
			if strings.HasPrefix(h.URL, "https://") && strings.HasPrefix(existing.URL, "http://") {
				seen[hostname] = h
			}
		}
	}

	result := make([]types.LiveHost, 0, len(seen))
	for _, h := range seen {
		result = append(result, h)
	}

	return result
}
