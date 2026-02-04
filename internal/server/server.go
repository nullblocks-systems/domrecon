package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nullblocks-systems/domrecon/internal/config"
	"github.com/nullblocks-systems/domrecon/internal/pipeline"
	"github.com/nullblocks-systems/domrecon/internal/types"
)

// Server provides HTTP API for domain reconnaissance
type Server struct {
	cfg    *config.Config
	server *http.Server
}

// New creates a new HTTP server
func New(cfg *config.Config) *Server {
	return &Server{
		cfg: cfg,
	}
}

// Run starts the HTTP server
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	// Web UI
	mux.HandleFunc("/", s.handleIndex)

	// Health check endpoint
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/healthz", s.handleHealth)

	// API endpoints
	mux.HandleFunc("/api/v1/scan", s.handleScan)
	mux.HandleFunc("/api/v1/scan/async", s.handleAsyncScan)

	s.server = &http.Server{
		Addr:         s.cfg.ServerAddr,
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 300 * time.Second, // Long timeout for scans
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.server.Shutdown(shutdownCtx)
	}()

	log.Printf("Starting server on %s", s.cfg.ServerAddr)
	if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}

	return nil
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	})
}

// ScanRequest represents a scan request
type ScanRequest struct {
	Domain     string   `json:"domain"`
	SkipNuclei bool     `json:"skip_nuclei,omitempty"`
	SkipPorts  bool     `json:"skip_ports,omitempty"`
	SkipDirs   bool     `json:"skip_dirs,omitempty"`
	Ports      []string `json:"ports,omitempty"`
}

// ScanResponse wraps the scan result
type ScanResponse struct {
	Success bool              `json:"success"`
	Data    *types.ScanResult `json:"data,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// AsyncScanResponse for async scan initiation
type AsyncScanResponse struct {
	Success bool   `json:"success"`
	JobID   string `json:"job_id,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		s.jsonError(w, "Domain is required", http.StatusBadRequest)
		return
	}

	// Create a scan-specific config
	scanCfg := *s.cfg
	if req.SkipNuclei {
		scanCfg.SkipNuclei = true
	}
	if req.SkipPorts {
		scanCfg.SkipPorts = true
	}
	if req.SkipDirs {
		scanCfg.SkipDirs = true
	}
	if len(req.Ports) > 0 {
		scanCfg.Ports = req.Ports
	}

	// Run the scan
	p := pipeline.New(&scanCfg)
	result, err := p.Run(r.Context(), req.Domain)
	if err != nil {
		s.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ScanResponse{
		Success: true,
		Data:    result,
	})
}

func (s *Server) handleAsyncScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		s.jsonError(w, "Domain is required", http.StatusBadRequest)
		return
	}

	// Generate a job ID
	jobID := generateJobID()

	// Start scan in background
	go func() {
		scanCfg := *s.cfg
		if req.SkipNuclei {
			scanCfg.SkipNuclei = true
		}
		if req.SkipPorts {
			scanCfg.SkipPorts = true
		}
		if req.SkipDirs {
			scanCfg.SkipDirs = true
		}
		if len(req.Ports) > 0 {
			scanCfg.Ports = req.Ports
		}

		p := pipeline.New(&scanCfg)
		result, err := p.Run(context.Background(), req.Domain)
		if err != nil {
			log.Printf("Async scan failed for %s: %v", req.Domain, err)
			return
		}

		// In a production system, you would store this result
		// For now, just log completion
		log.Printf("Async scan completed for %s: %d subdomains, %d live hosts, %d vulns",
			req.Domain, len(result.Subdomains), len(result.LiveHosts), len(result.Vulns))
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AsyncScanResponse{
		Success: true,
		JobID:   jobID,
		Message: "Scan started",
	})
}

func (s *Server) jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ScanResponse{
		Success: false,
		Error:   message,
	})
}

func generateJobID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DomRecon - Domain Reconnaissance</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        h1 { font-size: 2.5rem; margin-bottom: 0.5rem; background: linear-gradient(135deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { color: #94a3b8; margin-bottom: 2rem; }
        .card { background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #94a3b8; font-size: 0.875rem; }
        input[type="text"] { width: 100%; padding: 0.75rem 1rem; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 1rem; }
        input[type="text"]:focus { outline: none; border-color: #3b82f6; }
        .checkbox-group { display: flex; gap: 1.5rem; flex-wrap: wrap; }
        .checkbox-item { display: flex; align-items: center; gap: 0.5rem; }
        input[type="checkbox"] { width: 18px; height: 18px; accent-color: #3b82f6; }
        button { background: linear-gradient(135deg, #3b82f6, #8b5cf6); color: white; border: none; padding: 0.875rem 2rem; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
        button:hover { opacity: 0.9; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .results { margin-top: 2rem; }
        .results h2 { font-size: 1.25rem; margin-bottom: 1rem; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
        .stat { background: #0f172a; padding: 1rem; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2rem; font-weight: 700; color: #3b82f6; }
        .stat-label { font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; }
        .section { margin-bottom: 1.5rem; }
        .section-title { font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; color: #f8fafc; display: flex; align-items: center; gap: 0.5rem; }
        .badge { font-size: 0.75rem; background: #334155; padding: 0.25rem 0.5rem; border-radius: 4px; }
        .list { background: #0f172a; border-radius: 8px; max-height: 300px; overflow-y: auto; }
        .list-item { padding: 0.75rem 1rem; border-bottom: 1px solid #1e293b; font-family: monospace; font-size: 0.875rem; }
        .list-item:last-child { border-bottom: none; }
        .severity-low { color: #fbbf24; }
        .severity-medium { color: #f97316; }
        .severity-high { color: #ef4444; }
        .severity-critical { color: #dc2626; }
        .severity-info { color: #3b82f6; }
        .loading { display: flex; align-items: center; gap: 0.75rem; color: #94a3b8; }
        .spinner { width: 20px; height: 20px; border: 2px solid #334155; border-top-color: #3b82f6; border-radius: 50%; animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .error { background: #7f1d1d; border-color: #dc2626; }
        .time { color: #94a3b8; font-size: 0.875rem; }
        pre { background: #0f172a; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.75rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 DomRecon</h1>
        <p class="subtitle">Domain Reconnaissance & Security Analysis</p>
        
        <div class="card">
            <form id="scanForm">
                <div class="form-group">
                    <label for="domain">Target Domain</label>
                    <input type="text" id="domain" name="domain" placeholder="example.com" required>
                </div>
                <div class="form-group">
                    <label>Options</label>
                    <div class="checkbox-group">
                        <label class="checkbox-item">
                            <input type="checkbox" id="skipPorts" name="skip_ports">
                            <span>Skip Port Scan</span>
                        </label>
                        <label class="checkbox-item">
                            <input type="checkbox" id="skipDirs" name="skip_dirs">
                            <span>Skip Directory Scan</span>
                        </label>
                        <label class="checkbox-item">
                            <input type="checkbox" id="skipNuclei" name="skip_nuclei">
                            <span>Skip Vuln Scan</span>
                        </label>
                    </div>
                </div>
                <button type="submit" id="submitBtn">Run Scan</button>
            </form>
        </div>

        <div id="loading" style="display: none;" class="card">
            <div class="loading">
                <div class="spinner"></div>
                <span>Scanning... This typically takes 5-15 seconds</span>
            </div>
        </div>

        <div id="results" style="display: none;" class="results">
            <div class="card">
                <h2>Scan Results</h2>
                <p class="time" id="scanTime"></p>
                
                <div class="stats" id="stats"></div>

                <div class="section">
                    <div class="section-title">Subdomains <span class="badge" id="subdomainCount">0</span></div>
                    <div class="list" id="subdomainList"></div>
                </div>

                <div class="section">
                    <div class="section-title">Live Hosts <span class="badge" id="hostCount">0</span></div>
                    <div class="list" id="hostList"></div>
                </div>

                <div class="section">
                    <div class="section-title">Open Ports <span class="badge" id="portCount">0</span></div>
                    <div class="list" id="portList"></div>
                </div>

                <div class="section">
                    <div class="section-title">Vulnerabilities <span class="badge" id="vulnCount">0</span></div>
                    <div class="list" id="vulnList"></div>
                </div>

                <div class="section">
                    <div class="section-title">Header Issues <span class="badge" id="headerCount">0</span></div>
                    <div class="list" id="headerList"></div>
                </div>
            </div>
        </div>

        <div id="error" style="display: none;" class="card error"></div>
    </div>

    <script>
        const form = document.getElementById('scanForm');
        const loading = document.getElementById('loading');
        const results = document.getElementById('results');
        const errorDiv = document.getElementById('error');
        const submitBtn = document.getElementById('submitBtn');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const domain = document.getElementById('domain').value.trim();
            if (!domain) return;

            loading.style.display = 'block';
            results.style.display = 'none';
            errorDiv.style.display = 'none';
            submitBtn.disabled = true;

            try {
                const response = await fetch('/api/v1/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        domain: domain,
                        skip_ports: document.getElementById('skipPorts').checked,
                        skip_dirs: document.getElementById('skipDirs').checked,
                        skip_nuclei: document.getElementById('skipNuclei').checked
                    })
                });

                const data = await response.json();
                
                if (!data.success) {
                    throw new Error(data.error || 'Scan failed');
                }

                displayResults(data.data);
            } catch (err) {
                errorDiv.textContent = 'Error: ' + err.message;
                errorDiv.style.display = 'block';
            } finally {
                loading.style.display = 'none';
                submitBtn.disabled = false;
            }
        });

        function displayResults(data) {
            const duration = ((new Date(data.end_time) - new Date(data.start_time)) / 1000).toFixed(2);
            document.getElementById('scanTime').textContent = 'Completed in ' + duration + 's for ' + data.domain;

            document.getElementById('stats').innerHTML = 
                '<div class="stat"><div class="stat-value">' + (data.subdomains?.length || 0) + '</div><div class="stat-label">Subdomains</div></div>' +
                '<div class="stat"><div class="stat-value">' + (data.live_hosts?.length || 0) + '</div><div class="stat-label">Live Hosts</div></div>' +
                '<div class="stat"><div class="stat-value">' + (data.open_ports?.length || 0) + '</div><div class="stat-label">Open Ports</div></div>' +
                '<div class="stat"><div class="stat-value">' + (data.vulnerabilities?.length || 0) + '</div><div class="stat-label">Vulnerabilities</div></div>';

            document.getElementById('subdomainCount').textContent = data.subdomains?.length || 0;
            document.getElementById('subdomainList').innerHTML = (data.subdomains || [])
                .map(s => '<div class="list-item">' + s.name + ' <span style="color:#64748b">(' + s.source + ')</span></div>').join('');

            document.getElementById('hostCount').textContent = data.live_hosts?.length || 0;
            document.getElementById('hostList').innerHTML = (data.live_hosts || [])
                .map(h => '<div class="list-item">' + h.url + ' [' + h.status_code + '] ' + (h.title || '') + '</div>').join('');

            document.getElementById('portCount').textContent = data.open_ports?.length || 0;
            document.getElementById('portList').innerHTML = (data.open_ports || [])
                .map(p => '<div class="list-item">' + p.host + ':' + p.port + ' (' + p.service + ')</div>').join('');

            document.getElementById('vulnCount').textContent = data.vulnerabilities?.length || 0;
            document.getElementById('vulnList').innerHTML = (data.vulnerabilities || [])
                .map(v => '<div class="list-item"><span class="severity-' + v.severity + '">[' + v.severity.toUpperCase() + ']</span> ' + v.name + '</div>').join('');

            const headerIssues = data.analysis?.header_issues || [];
            document.getElementById('headerCount').textContent = headerIssues.length;
            document.getElementById('headerList').innerHTML = headerIssues
                .map(h => '<div class="list-item">' + h.issue + ': ' + h.header + (h.details ? ' - ' + h.details : '') + '</div>').join('');

            results.style.display = 'block';
        }
    </script>
</body>
</html>`
