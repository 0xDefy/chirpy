package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
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
	serveMux.HandleFunc("GET /api/healthz", healthzHandle)
	serveMux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetMetricsHandler)
	serveMux.HandleFunc("POST /api/validate_chirp", apiCfg.validateChirpHandler)
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
	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(200)
	x := cfg.fileServerHits.Load()
	y := fmt.Sprintf(`
		<html>
  			<body>
    			<h1>Welcome, Chirpy Admin</h1>
    			<p>Chirpy has been visited %d times!</p>
    		</body>
		</html>
	`, x)
	w.Write([]byte(y))
}

func (cfg *apiConfig) resetMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	cfg.fileServerHits.Swap(0)
	w.Write([]byte("Hits: 0"))
}

func (cfg *apiConfig) validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	type returnVals struct {
		Error string `json:"error"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("error decoding parameters: %s", err)
		resErrBody := returnVals{
			Error: "Something went wrong",
		}
		dat, err := json.Marshal(resErrBody)
		if err != nil {
			log.Printf("error marshaling error json: %s", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write(dat)
		return
	}
	params.Body = strings.TrimSpace(params.Body)
	if len(params.Body) > 140 {
		log.Println("too many characters in body")
		resErrBody := returnVals{
			Error: "Chirp is too long",
		}
		dat, err := json.Marshal(resErrBody)
		if err != nil {
			log.Printf("error marshaling error json: %s", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write(dat)
		return
	}
	type successResponse struct {
		Valid bool `json:"valid"`
	}
	respBody := successResponse{
		Valid: true,
	}
	dat, err := json.Marshal(respBody)
	if err != nil {
		log.Printf("error marshaling json: %s", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(dat)
}
