package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nullblocks-systems/domrecon/internal/types"
)

//go:embed wordlists/quickhits.txt
var embeddedWordlists embed.FS

// DirScanner performs directory enumeration
type DirScanner struct {
	client      *http.Client
	wordlist    []string
	concurrency int
}

// NewDirScanner creates a new directory scanner
func NewDirScanner(wordlistPath string, concurrency int) (*DirScanner, error) {
	var wordlist []string
	var err error

	if wordlistPath != "" {
		wordlist, err = loadWordlistFromFile(wordlistPath)
	} else {
		wordlist, err = loadEmbeddedWordlist()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 2 * time.Second,
		}).DialContext,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       10 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
	}

	return &DirScanner{
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		wordlist:    wordlist,
		concurrency: concurrency * 5, // Increase concurrency for dir scanning
	}, nil
}

// Scan performs directory enumeration on the given URLs
func (s *DirScanner) Scan(ctx context.Context, urls []string) ([]types.DirResult, error) {
	var (
		mu      sync.Mutex
		results []types.DirResult
		wg      sync.WaitGroup
		sem     = make(chan struct{}, s.concurrency)
	)

	type scanTarget struct {
		baseURL string
		path    string
	}

	// Generate all URL/path combinations
	var targets []scanTarget
	for _, url := range urls {
		url = strings.TrimSuffix(url, "/")
		for _, path := range s.wordlist {
			targets = append(targets, scanTarget{url, path})
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

			result, err := s.checkPath(ctx, t.baseURL, t.path)
			if err != nil {
				return
			}

			// Only include successful responses (200-299)
			if result.StatusCode >= 200 && result.StatusCode < 300 {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	return results, nil
}

func (s *DirScanner) checkPath(ctx context.Context, baseURL, path string) (*types.DirResult, error) {
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	url := baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; domrecon/1.0)")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &types.DirResult{
		URL:        url,
		StatusCode: resp.StatusCode,
		Size:       int(resp.ContentLength),
	}, nil
}

func loadWordlistFromFile(path string) ([]string, error) {
	// This would load from external file
	// For now, fall back to embedded
	return loadEmbeddedWordlist()
}

func loadEmbeddedWordlist() ([]string, error) {
	data, err := embeddedWordlists.ReadFile("wordlists/quickhits.txt")
	if err != nil {
		// Return a minimal default wordlist if embedded file not found
		return getDefaultWordlist(), nil
	}

	var wordlist []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			wordlist = append(wordlist, line)
		}
	}

	if len(wordlist) == 0 {
		return getDefaultWordlist(), nil
	}

	return wordlist, nil
}

func getDefaultWordlist() []string {
	return []string{
		".git/HEAD",
		".git/config",
		".env",
		".htaccess",
		".htpasswd",
		"admin",
		"admin/",
		"administrator",
		"api",
		"api/",
		"api/v1",
		"api/v2",
		"backup",
		"backup.sql",
		"backup.zip",
		"config",
		"config.php",
		"config.yml",
		"console",
		"dashboard",
		"db",
		"debug",
		"dev",
		"docs",
		"graphql",
		"health",
		"info.php",
		"login",
		"metrics",
		"phpinfo.php",
		"phpmyadmin",
		"robots.txt",
		"server-status",
		"sitemap.xml",
		"status",
		"swagger",
		"swagger.json",
		"swagger-ui",
		"test",
		"uploads",
		"wp-admin",
		"wp-config.php",
		"wp-content",
		"wp-login.php",
		".well-known/security.txt",
		"actuator",
		"actuator/health",
		"actuator/env",
		"trace",
		"elmah.axd",
		"web.config",
	}
}
