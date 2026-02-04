package analysis

import (
	"context"
	"regexp"
	"strings"

	"github.com/nullblocks-systems/domrecon/internal/types"
)

// Analyzer performs content analysis on fetched pages
type Analyzer struct {
	domain string
}

// NewAnalyzer creates a new content analyzer
func NewAnalyzer(domain string) *Analyzer {
	return &Analyzer{
		domain: domain,
	}
}

// Analyze performs analysis on live hosts
func (a *Analyzer) Analyze(ctx context.Context, hosts []types.LiveHost) (*types.AnalysisResult, error) {
	result := &types.AnalysisResult{
		Secrets:       []types.SecretFinding{},
		VulnLibs:      []types.VulnLib{},
		HeaderIssues:  []types.HeaderIssue{},
		Links:         []string{},
		NewSubdomains: []string{},
	}

	for _, host := range hosts {
		// Analyze headers for security issues
		headerIssues := a.analyzeHeaders(host)
		result.HeaderIssues = append(result.HeaderIssues, headerIssues...)
	}

	return result, nil
}

// AnalyzeBody analyzes HTML body content for secrets and vulnerabilities
func (a *Analyzer) AnalyzeBody(url, body string) (*types.AnalysisResult, error) {
	result := &types.AnalysisResult{
		Secrets:       []types.SecretFinding{},
		VulnLibs:      []types.VulnLib{},
		Links:         []string{},
		NewSubdomains: []string{},
	}

	// Find secrets
	secrets := a.findSecrets(url, body)
	result.Secrets = append(result.Secrets, secrets...)

	// Find vulnerable libraries
	vulnLibs := a.findVulnLibs(url, body)
	result.VulnLibs = append(result.VulnLibs, vulnLibs...)

	// Extract links
	links := a.extractLinks(body)
	result.Links = append(result.Links, links...)

	// Find new subdomains
	subdomains := a.findSubdomains(body)
	result.NewSubdomains = append(result.NewSubdomains, subdomains...)

	return result, nil
}

// analyzeHeaders checks for security header issues
func (a *Analyzer) analyzeHeaders(host types.LiveHost) []types.HeaderIssue {
	var issues []types.HeaderIssue

	// Security headers to check
	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Permissions-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy",
	}

	for _, header := range securityHeaders {
		if _, ok := host.Headers[header]; !ok {
			issues = append(issues, types.HeaderIssue{
				URL:    host.URL,
				Issue:  "missing_security_header",
				Header: header,
			})
		}
	}

	// Check for information disclosure
	if server, ok := host.Headers["Server"]; ok {
		issues = append(issues, types.HeaderIssue{
			URL:     host.URL,
			Issue:   "server_disclosure",
			Header:  "Server",
			Details: server,
		})
	}

	if powered, ok := host.Headers["X-Powered-By"]; ok {
		issues = append(issues, types.HeaderIssue{
			URL:     host.URL,
			Issue:   "technology_disclosure",
			Header:  "X-Powered-By",
			Details: powered,
		})
	}

	// Check cookie security
	if setCookie, ok := host.Headers["Set-Cookie"]; ok {
		if !strings.Contains(strings.ToLower(setCookie), "secure") {
			issues = append(issues, types.HeaderIssue{
				URL:     host.URL,
				Issue:   "cookie_missing_secure",
				Header:  "Set-Cookie",
				Details: "Cookie missing Secure flag",
			})
		}
		if !strings.Contains(strings.ToLower(setCookie), "httponly") {
			issues = append(issues, types.HeaderIssue{
				URL:     host.URL,
				Issue:   "cookie_missing_httponly",
				Header:  "Set-Cookie",
				Details: "Cookie missing HttpOnly flag",
			})
		}
		if !strings.Contains(strings.ToLower(setCookie), "samesite") {
			issues = append(issues, types.HeaderIssue{
				URL:     host.URL,
				Issue:   "cookie_missing_samesite",
				Header:  "Set-Cookie",
				Details: "Cookie missing SameSite attribute",
			})
		}
	}

	// Check CORS
	if cors, ok := host.Headers["Access-Control-Allow-Origin"]; ok {
		if cors == "*" {
			issues = append(issues, types.HeaderIssue{
				URL:     host.URL,
				Issue:   "cors_wildcard",
				Header:  "Access-Control-Allow-Origin",
				Details: "Overly permissive CORS: *",
			})
		}
	}

	return issues
}

// findSecrets searches for potential secrets in content
func (a *Analyzer) findSecrets(url, body string) []types.SecretFinding {
	var findings []types.SecretFinding

	patterns := map[string]*regexp.Regexp{
		"aws_access_key":    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"google_api_key":    regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		"stripe_live_key":   regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
		"jwt_token":         regexp.MustCompile(`eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}`),
		"private_key":       regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		"github_token":      regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`),
		"slack_token":       regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
		"generic_api_key":   regexp.MustCompile(`(?i)(api[_-]?key|apikey|api_secret)['":\s]*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`),
		"generic_secret":    regexp.MustCompile(`(?i)(secret|password|passwd|pwd)['":\s]*[=:]\s*['"]?([^\s'"]{8,})['"]?`),
		"generic_token":     regexp.MustCompile(`(?i)(token|bearer|auth)['":\s]*[=:]\s*['"]?([a-zA-Z0-9_\-\.]{20,})['"]?`),
		"aws_secret_key":    regexp.MustCompile(`(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]`),
		"heroku_api_key":    regexp.MustCompile(`[hH]eroku[a-zA-Z0-9]{0,20}['\"][0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}['\"]`),
		"mailgun_api_key":   regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		"twilio_api_key":    regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		"sendgrid_api_key":  regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
	}

	for secretType, pattern := range patterns {
		matches := pattern.FindAllString(body, -1)
		for _, match := range matches {
			// Get context around the match
			idx := strings.Index(body, match)
			start := max(0, idx-50)
			end := min(len(body), idx+len(match)+50)
			context := body[start:end]

			findings = append(findings, types.SecretFinding{
				URL:     url,
				Type:    secretType,
				Match:   match,
				Context: strings.TrimSpace(context),
			})
		}
	}

	return findings
}

// findVulnLibs searches for potentially vulnerable JavaScript libraries
func (a *Analyzer) findVulnLibs(url, body string) []types.VulnLib {
	var libs []types.VulnLib

	// Pattern to find script tags with src
	scriptPattern := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptPattern.FindAllStringSubmatch(body, -1)

	// Known vulnerable library patterns
	vulnPatterns := map[string]*regexp.Regexp{
		"jquery":     regexp.MustCompile(`jquery[.-]?(\d+\.\d+\.\d+)?`),
		"angular":    regexp.MustCompile(`angular[.-]?(\d+\.\d+\.\d+)?`),
		"bootstrap":  regexp.MustCompile(`bootstrap[.-]?(\d+\.\d+\.\d+)?`),
		"react":      regexp.MustCompile(`react[.-]?(\d+\.\d+\.\d+)?`),
		"vue":        regexp.MustCompile(`vue[.-]?(\d+\.\d+\.\d+)?`),
		"lodash":     regexp.MustCompile(`lodash[.-]?(\d+\.\d+\.\d+)?`),
		"moment":     regexp.MustCompile(`moment[.-]?(\d+\.\d+\.\d+)?`),
		"underscore": regexp.MustCompile(`underscore[.-]?(\d+\.\d+\.\d+)?`),
	}

	for _, match := range matches {
		if len(match) > 1 {
			src := match[1]
			for libName, pattern := range vulnPatterns {
				if libMatch := pattern.FindStringSubmatch(strings.ToLower(src)); libMatch != nil {
					version := ""
					if len(libMatch) > 1 {
						version = libMatch[1]
					}
					libs = append(libs, types.VulnLib{
						URL:     url,
						Library: libName,
						Version: version,
					})
				}
			}
		}
	}

	return libs
}

// extractLinks extracts all links from HTML content
func (a *Analyzer) extractLinks(body string) []string {
	var links []string
	seen := make(map[string]bool)

	// Find href attributes
	hrefPattern := regexp.MustCompile(`href=["']([^"']+)["']`)
	hrefMatches := hrefPattern.FindAllStringSubmatch(body, -1)
	for _, match := range hrefMatches {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			links = append(links, match[1])
		}
	}

	// Find src attributes
	srcPattern := regexp.MustCompile(`src=["']([^"']+)["']`)
	srcMatches := srcPattern.FindAllStringSubmatch(body, -1)
	for _, match := range srcMatches {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			links = append(links, match[1])
		}
	}

	return links
}

// findSubdomains extracts subdomains from content
func (a *Analyzer) findSubdomains(body string) []string {
	var subdomains []string
	seen := make(map[string]bool)

	// Pattern to find subdomains of the target domain
	pattern := regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9._-]*\.` + regexp.QuoteMeta(a.domain))
	matches := pattern.FindAllString(body, -1)

	for _, match := range matches {
		match = strings.ToLower(match)
		if !seen[match] {
			seen[match] = true
			subdomains = append(subdomains, match)
		}
	}

	return subdomains
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
