package pipeline

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/nullblocks-systems/domrecon/internal/analysis"
	"github.com/nullblocks-systems/domrecon/internal/config"
	"github.com/nullblocks-systems/domrecon/internal/discovery"
	"github.com/nullblocks-systems/domrecon/internal/scanner"
	"github.com/nullblocks-systems/domrecon/internal/types"
)

// Pipeline orchestrates the reconnaissance workflow
type Pipeline struct {
	cfg *config.Config
}

// New creates a new pipeline
func New(cfg *config.Config) *Pipeline {
	return &Pipeline{cfg: cfg}
}

// Run executes the full reconnaissance pipeline
func (p *Pipeline) Run(ctx context.Context, domain string) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Domain:    domain,
		StartTime: time.Now(),
		Errors:    []string{},
	}

	if p.cfg.Verbose {
		log.Printf("[*] Starting reconnaissance on %s", domain)
	}

	// Stage 1: Subdomain Discovery
	if p.cfg.Verbose {
		log.Printf("[*] Stage 1: Subdomain Discovery")
	}
	subdomains, err := p.discoverSubdomains(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("subdomain discovery: %v", err))
	} else {
		result.Subdomains = subdomains
		if p.cfg.Verbose {
			log.Printf("[+] Found %d subdomains", len(subdomains))
		}
	}

	// Stage 2: HTTP Probing
	if p.cfg.Verbose {
		log.Printf("[*] Stage 2: HTTP Probing")
	}
	liveHosts, err := p.probeHosts(ctx, subdomains)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("http probing: %v", err))
	} else {
		result.LiveHosts = liveHosts
		if p.cfg.Verbose {
			log.Printf("[+] Found %d live hosts", len(liveHosts))
		}
	}

	// Stage 3: Port Scanning (optional)
	if !p.cfg.SkipPorts {
		if p.cfg.Verbose {
			log.Printf("[*] Stage 3: Port Scanning")
		}
		ports, err := p.scanPorts(ctx, subdomains)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("port scanning: %v", err))
		} else {
			result.OpenPorts = ports
			if p.cfg.Verbose {
				log.Printf("[+] Found %d open ports", len(ports))
			}
		}
	}

	// Stage 4: Vulnerability Scanning (optional)
	if !p.cfg.SkipNuclei {
		if p.cfg.Verbose {
			log.Printf("[*] Stage 4: Vulnerability Scanning")
		}
		vulns, err := p.scanVulnerabilities(ctx, liveHosts)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("vulnerability scanning: %v", err))
		} else {
			result.Vulns = vulns
			if p.cfg.Verbose {
				log.Printf("[+] Found %d vulnerabilities", len(vulns))
			}
		}
	}

	// Stage 5: Directory Enumeration (optional)
	if !p.cfg.SkipDirs {
		if p.cfg.Verbose {
			log.Printf("[*] Stage 5: Directory Enumeration")
		}
		dirs, err := p.scanDirectories(ctx, liveHosts)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("directory enumeration: %v", err))
		} else {
			result.Directories = dirs
			if p.cfg.Verbose {
				log.Printf("[+] Found %d directories", len(dirs))
			}
		}
	}

	// Stage 6: Content Analysis
	if p.cfg.Verbose {
		log.Printf("[*] Stage 6: Content Analysis")
	}
	analysisResult, err := p.analyzeContent(ctx, domain, liveHosts)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("content analysis: %v", err))
	} else {
		result.Analysis = *analysisResult
	}

	result.EndTime = time.Now()

	if p.cfg.Verbose {
		log.Printf("[*] Scan completed in %s", result.EndTime.Sub(result.StartTime))
	}

	return result, nil
}

func (p *Pipeline) discoverSubdomains(ctx context.Context, domain string) ([]types.Subdomain, error) {
	finder := discovery.NewSubdomainFinder(p.cfg.Concurrency)
	return finder.Find(ctx, domain)
}

func (p *Pipeline) probeHosts(ctx context.Context, subdomains []types.Subdomain) ([]types.LiveHost, error) {
	prober := discovery.NewHTTPProber(p.cfg.Concurrency)
	return prober.Probe(ctx, subdomains)
}

func (p *Pipeline) scanPorts(ctx context.Context, subdomains []types.Subdomain) ([]types.PortResult, error) {
	ports, err := scanner.ParsePorts(p.cfg.Ports)
	if err != nil {
		return nil, err
	}

	// Extract hostnames from subdomains
	var hosts []string
	for _, sub := range subdomains {
		hosts = append(hosts, sub.Name)
	}

	portScanner := scanner.NewPortScanner(ports, p.cfg.Concurrency)
	return portScanner.Scan(ctx, hosts)
}

func (p *Pipeline) scanVulnerabilities(ctx context.Context, hosts []types.LiveHost) ([]types.VulnResult, error) {
	vulnScanner := scanner.NewVulnScanner(p.cfg.TemplatesPath, p.cfg.Concurrency)
	return vulnScanner.Scan(ctx, hosts)
}

func (p *Pipeline) scanDirectories(ctx context.Context, hosts []types.LiveHost) ([]types.DirResult, error) {
	dirScanner, err := scanner.NewDirScanner(p.cfg.WordlistPath, p.cfg.Concurrency)
	if err != nil {
		return nil, err
	}

	// Extract URLs from live hosts
	var urls []string
	for _, host := range hosts {
		urls = append(urls, host.URL)
	}

	return dirScanner.Scan(ctx, urls)
}

func (p *Pipeline) analyzeContent(ctx context.Context, domain string, hosts []types.LiveHost) (*types.AnalysisResult, error) {
	analyzer := analysis.NewAnalyzer(domain)
	return analyzer.Analyze(ctx, hosts)
}

// ExtractHostsFromPorts returns unique hosts that have HTTP/HTTPS ports open
func ExtractHostsFromPorts(ports []types.PortResult) []string {
	seen := make(map[string]bool)
	var hosts []string

	httpPorts := map[int]bool{80: true, 443: true, 8080: true, 8443: true, 8000: true, 8888: true}

	for _, p := range ports {
		if httpPorts[p.Port] && !seen[p.Host] {
			seen[p.Host] = true
			hosts = append(hosts, p.Host)
		}
	}

	return hosts
}

// BuildURLsFromPorts constructs URLs from port scan results
func BuildURLsFromPorts(ports []types.PortResult) []string {
	var urls []string

	for _, p := range ports {
		var scheme string
		switch p.Port {
		case 443, 8443:
			scheme = "https"
		case 80, 8080, 8000, 8888:
			scheme = "http"
		default:
			if strings.Contains(p.Service, "ssl") || strings.Contains(p.Service, "https") {
				scheme = "https"
			} else if strings.Contains(p.Service, "http") {
				scheme = "http"
			} else {
				continue
			}
		}

		url := fmt.Sprintf("%s://%s:%d", scheme, p.Host, p.Port)
		urls = append(urls, url)
	}

	return urls
}
