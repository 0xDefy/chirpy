package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileServerHits atomic.Int32
}

// All helper functions
func cleanText(input string) string {
	// Define words to censor
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}

	// Create a regex pattern to match whole words (case insensitive)
	for _, word := range profaneWords {
		// Use raw string literals (backticks) to avoid needing to escape backslashes
		pattern := `(?i)\b` + regexp.QuoteMeta(word) + `\b`
		re := regexp.MustCompile(pattern)
		input = re.ReplaceAllString(input, "****")
	}

	return input
}

// respondWithError sends an error response with the given status code and message
func respondWithError(w http.ResponseWriter, code int, msg string) {
	// Create a response that includes the error message
	type errorResponse struct {
		Error string `json:"error"`
	}

	respBody := errorResponse{
		Error: msg,
	}

	// Marshal the response to JSON
	jsonResp, err := json.Marshal(respBody)
	if err != nil {
		// If marshaling fails, log the error and return a basic 500 error
		log.Printf("Error marshaling JSON: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
		return
	}

	// Set headers and write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jsonResp)
}

// respondWithJSON sends a success response with the given status code and payload
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	// Marshal the payload to JSON
	jsonResp, err := json.Marshal(payload)
	if err != nil {
		// If marshaling fails, log the error and return a basic 500 error
		log.Printf("Error marshaling JSON: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Set headers and write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jsonResp)
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
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("error decoding parameters: %s", err)
		respondWithError(w, 500, "Something went wrong")
		return
	}
	params.Body = strings.TrimSpace(params.Body)
	if len(params.Body) > 140 {
		log.Println("too many characters in body")
		respondWithError(w, 400, "Chirp is too long")
		return
	}
	type successResponse struct {
		CleanedBody string `json:"cleaned_body"`
	}
	cleanedString := cleanText(params.Body)
	respBody := successResponse{
		CleanedBody: cleanedString,
	}
	respondWithJSON(w, 200, respBody)
}
