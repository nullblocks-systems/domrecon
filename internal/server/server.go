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
