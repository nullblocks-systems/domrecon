package types

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// ScanResult holds all reconnaissance data for a domain
type ScanResult struct {
	Domain      string        `json:"domain"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Subdomains  []Subdomain   `json:"subdomains"`
	LiveHosts   []LiveHost    `json:"live_hosts"`
	OpenPorts   []PortResult  `json:"open_ports"`
	Directories []DirResult   `json:"directories"`
	Vulns       []VulnResult  `json:"vulnerabilities"`
	Analysis    AnalysisResult `json:"analysis"`
	Errors      []string      `json:"errors,omitempty"`
}

// Subdomain represents a discovered subdomain
type Subdomain struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// LiveHost represents a host responding to HTTP/HTTPS
type LiveHost struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Title      string            `json:"title,omitempty"`
	BodySize   int               `json:"body_size"`
}

// PortResult represents an open port on a host
type PortResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	State   string `json:"state"`
}

// DirResult represents a discovered directory/path
type DirResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Size       int    `json:"size"`
}

// VulnResult represents a vulnerability finding
type VulnResult struct {
	Template    string   `json:"template"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched_at"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// AnalysisResult holds content analysis findings
type AnalysisResult struct {
	Secrets       []SecretFinding `json:"secrets,omitempty"`
	VulnLibs      []VulnLib       `json:"vulnerable_libraries,omitempty"`
	HeaderIssues  []HeaderIssue   `json:"header_issues,omitempty"`
	Links         []string        `json:"links,omitempty"`
	NewSubdomains []string        `json:"new_subdomains,omitempty"`
}

// SecretFinding represents a potential secret/credential leak
type SecretFinding struct {
	URL     string `json:"url"`
	Type    string `json:"type"`
	Match   string `json:"match"`
	Context string `json:"context,omitempty"`
}

// VulnLib represents a potentially vulnerable JavaScript library
type VulnLib struct {
	URL     string `json:"url"`
	Library string `json:"library"`
	Version string `json:"version,omitempty"`
}

// HeaderIssue represents a security header problem
type HeaderIssue struct {
	URL     string `json:"url"`
	Issue   string `json:"issue"`
	Header  string `json:"header,omitempty"`
	Details string `json:"details,omitempty"`
}

// Output writes the scan results to the specified format and destination
func (r *ScanResult) Output(format, outputFile string) error {
	var w io.Writer = os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "text":
		return r.outputText(w)
	default:
		return fmt.Errorf("unknown output format: %s", format)
	}
}

func (r *ScanResult) outputText(w io.Writer) error {
	fmt.Fprintf(w, "=== Domain Reconnaissance Report ===\n")
	fmt.Fprintf(w, "Domain: %s\n", r.Domain)
	fmt.Fprintf(w, "Scan Duration: %s\n\n", r.EndTime.Sub(r.StartTime))

	fmt.Fprintf(w, "--- Subdomains (%d) ---\n", len(r.Subdomains))
	for _, s := range r.Subdomains {
		fmt.Fprintf(w, "  %s [%s]\n", s.Name, s.Source)
	}

	fmt.Fprintf(w, "\n--- Live Hosts (%d) ---\n", len(r.LiveHosts))
	for _, h := range r.LiveHosts {
		fmt.Fprintf(w, "  %s [%d] %s\n", h.URL, h.StatusCode, h.Title)
	}

	fmt.Fprintf(w, "\n--- Open Ports (%d) ---\n", len(r.OpenPorts))
	for _, p := range r.OpenPorts {
		fmt.Fprintf(w, "  %s:%d (%s)\n", p.Host, p.Port, p.Service)
	}

	fmt.Fprintf(w, "\n--- Directories (%d) ---\n", len(r.Directories))
	for _, d := range r.Directories {
		fmt.Fprintf(w, "  %s [%d]\n", d.URL, d.StatusCode)
	}

	fmt.Fprintf(w, "\n--- Vulnerabilities (%d) ---\n", len(r.Vulns))
	for _, v := range r.Vulns {
		fmt.Fprintf(w, "  [%s] %s @ %s\n", v.Severity, v.Name, v.MatchedAt)
	}

	fmt.Fprintf(w, "\n--- Analysis ---\n")
	fmt.Fprintf(w, "  Secrets Found: %d\n", len(r.Analysis.Secrets))
	fmt.Fprintf(w, "  Vulnerable Libraries: %d\n", len(r.Analysis.VulnLibs))
	fmt.Fprintf(w, "  Header Issues: %d\n", len(r.Analysis.HeaderIssues))

	if len(r.Errors) > 0 {
		fmt.Fprintf(w, "\n--- Errors ---\n")
		for _, e := range r.Errors {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}

	return nil
}
