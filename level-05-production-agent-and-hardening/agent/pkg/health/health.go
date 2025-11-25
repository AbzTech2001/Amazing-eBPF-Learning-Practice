package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// CheckFunc is a health check function
type CheckFunc func() error

// Status represents health status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
)

// CheckResult represents result of a health check
type CheckResult struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message,omitempty"`
}

// HealthResponse is the overall health response
type HealthResponse struct {
	Status    Status        `json:"status"`
	Timestamp time.Time     `json:"timestamp"`
	Checks    []CheckResult `json:"checks"`
}

// Server provides health check HTTP endpoints
type Server struct {
	port   int
	checks map[string]CheckFunc
	mu     sync.RWMutex
	server *http.Server
}

func NewServer(port int) (*Server, error) {
	return &Server{
		port:   port,
		checks: make(map[string]CheckFunc),
	}, nil
}

// RegisterCheck registers a named health check
func (s *Server) RegisterCheck(name string, check CheckFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks[name] = check
}

// Start starts the health check server
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)
	mux.HandleFunc("/live", s.handleLive)

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Health server error: %v\n", err)
		}
	}()

	return nil
}

// Stop stops the health server
func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}

// handleHealth returns comprehensive health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	response := HealthResponse{
		Timestamp: time.Now(),
		Checks:    make([]CheckResult, 0, len(s.checks)),
	}

	overallHealthy := true
	anyDegraded := false

	for name, check := range s.checks {
		result := CheckResult{Name: name}

		if err := check(); err != nil {
			result.Status = StatusUnhealthy
			result.Message = err.Error()
			overallHealthy = false
		} else {
			result.Status = StatusHealthy
		}

		response.Checks = append(response.Checks, result)
	}

	if !overallHealthy {
		response.Status = StatusUnhealthy
		w.WriteHeader(http.StatusServiceUnavailable)
	} else if anyDegraded {
		response.Status = StatusDegraded
		w.WriteHeader(http.StatusOK)
	} else {
		response.Status = StatusHealthy
		w.WriteHeader(http.StatusOK)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleReady returns 200 if ready to serve traffic (Kubernetes readiness)
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, check := range s.checks {
		if err := check(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Not ready"))
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ready"))
}

// handleLive returns 200 if process is alive (Kubernetes liveness)
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Alive"))
}

/*
 * Health Check Patterns:
 *
 * 1. /health - Detailed status of all components
 *    - Used for monitoring dashboards
 *    - Returns JSON with all check results
 *
 * 2. /ready - Kubernetes readiness probe
 *    - Returns 200 only if ready to serve traffic
 *    - Used by load balancer to route traffic
 *
 * 3. /live - Kubernetes liveness probe
 *    - Returns 200 if process is alive
 *    - K8s restarts pod if this fails
 *
 * Kubernetes Integration:
 *
 * livenessProbe:
 *   httpGet:
 *     path: /live
 *     port: 8080
 *   initialDelaySeconds: 30
 *   periodSeconds: 10
 *
 * readinessProbe:
 *   httpGet:
 *     path: /ready
 *     port: 8080
 *   initialDelaySeconds: 5
 *   periodSeconds: 5
 */
