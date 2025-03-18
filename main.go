package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileServerHits atomic.Int32
}

func main() {
	apiCfg := apiConfig{}
	serveMux := http.NewServeMux()
	serveMux.Handle("/app/",
		apiCfg.middlewareMetricsInc(
			http.StripPrefix(
				"/app/", http.FileServer(
					http.Dir(".")))))
	serveMux.HandleFunc("GET /healthz", healthzHandle)
	serveMux.HandleFunc("GET /metrics", apiCfg.metricsHandler)
	serveMux.HandleFunc("POST /reset", apiCfg.resetMetricsHandler)
	server := &http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("error listening and serving: %v", err)
	}
}

func healthzHandle(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	x := cfg.fileServerHits.Load()
	y := fmt.Sprintf("Hits: %d", x)
	w.Write([]byte(y))
}

func (cfg *apiConfig) resetMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	cfg.fileServerHits.Swap(0)
	w.Write([]byte("Hits: 0"))
}
