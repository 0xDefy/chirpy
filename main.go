package main

import (
	// "context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xdefy/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileServerHits atomic.Int32
	DB             *database.Queries
	PLATFORM       string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
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
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("error connecting to database: %v", err)
	}
	dbQueries := database.New(db)
	apiCfg := apiConfig{
		DB:       dbQueries,
		PLATFORM: platform,
	}
	serveMux := http.NewServeMux()
	serveMux.Handle("/app/",
		apiCfg.middlewareMetricsInc(
			http.StripPrefix(
				"/app/", http.FileServer(
					http.Dir(".")))))
	serveMux.HandleFunc("GET /api/healthz", healthzHandle)
	serveMux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	serveMux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	serveMux.HandleFunc("POST /api/chirps", apiCfg.chirpsHandler)
	server := &http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}
	err = server.ListenAndServe()
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

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.PLATFORM != "dev" {
		respondWithError(w, 403, "Forbidden")
		return
	}
	err := cfg.DB.DeleteUsers(r.Context())
	if err != nil {
		log.Printf("error while deleting users %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to reset users")
		return
	}
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully deleted all users"))
}

func (cfg *apiConfig) chirpsHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body   string    `json:"body"`
		UserId uuid.UUID `json:"user_id"`
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
	dbParams := database.CreateChirpParams{
		Body:   params.Body,
		UserID: params.UserId,
	}
	dbChirps, err := cfg.DB.CreateChirp(r.Context(), dbParams)
	if err != nil {
		log.Printf("error uploading to database: %s", err)
		respondWithError(w, 500, "uploading to database failed")
		return
	}
	type chirpResponse struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	// Then convert dbChirps to this response format
	response := chirpResponse{
		ID:        dbChirps.ID,
		CreatedAt: dbChirps.CreatedAt,
		UpdatedAt: dbChirps.UpdatedAt,
		Body:      dbChirps.Body,
		UserID:    dbChirps.UserID,
	}
	respondWithJSON(w, 201, response)
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email string `json:"email"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("error decoding parameters: %s", err)
		respondWithError(w, 500, "Something went wrong")
		return
	}
	params.Email = strings.TrimSpace(params.Email)
	dbUser, err := cfg.DB.CreateUser(r.Context(), params.Email)
	if err != nil {
		log.Printf("error uploading to database: %s", err)
		respondWithError(w, 500, "uploading to database failed")
		return
	}
	user := User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}
	respondWithJSON(w, 201, user)
}
