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

	"github.com/0xdefy/chirpy/internal/auth"
	"github.com/0xdefy/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileServerHits atomic.Int32
	DB             *database.Queries
	PLATFORM       string
	JWTSecret      string
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
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("error connecting to database: %v", err)
	}
	dbQueries := database.New(db)
	apiCfg := apiConfig{
		DB:        dbQueries,
		PLATFORM:  platform,
		JWTSecret: jwtSecret,
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
	serveMux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpsByIdHandler)
	serveMux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	serveMux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	serveMux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)
	serveMux.HandleFunc("PUT /api/users", apiCfg.putUserHandler)
	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpsByIdHandler)
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
		Body string `json:"body"`
	}
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("error getting bearer token %s", err)
		respondWithError(w, 401, "Unauthorized")
		return
	}
	user_id, err := auth.ValidateJWT(tokenString, cfg.JWTSecret)
	if err != nil {
		log.Printf("jwt invalid: %s", err)
		respondWithError(w, 401, "Unauthorized")
		return
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
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
		UserID: user_id,
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
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("error decoding parameters: %s", err)
		respondWithError(w, 400, "Something went wrong")
		return
	}
	params.Email = strings.TrimSpace(params.Email)
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("error hashing password %v", err)
		respondWithError(w, 500, "hashing password failed")
		return
	}
	upParams := database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	}
	dbUser, err := cfg.DB.CreateUser(r.Context(), upParams)
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

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := cfg.DB.GetChirps(r.Context())
	if err != nil {
		log.Printf("error fetching chirps %s", err)
		respondWithError(w, 500, "fetching from database failed")
		return
	}
	type chirp struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}
	chirpArr := []chirp{}
	for _, dbChirp := range dbChirps {
		newChirp := chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
		}
		chirpArr = append(chirpArr, newChirp)
	}
	respondWithJSON(w, 200, chirpArr)
}

func (cfg *apiConfig) getChirpsByIdHandler(w http.ResponseWriter, r *http.Request) {
	chirpIDStr := r.PathValue("chirpID")

	// Convert string to UUID
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		// Handle invalid UUID
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}

	dbChirp, err := cfg.DB.GetChirpsById(r.Context(), chirpID)
	if err != nil {
		log.Printf("error fetching user by id %v", err)
		respondWithError(w, 404, "chirp not found")
		return
	}
	type chirp struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}
	newChirp := chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}
	respondWithJSON(w, 200, newChirp)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("error decoding parameters: %s", err)
		respondWithError(w, 400, "Something went wrong")
		return
	}
	params.Email = strings.TrimSpace(params.Email)
	dbUser, err := cfg.DB.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		log.Printf("no user found for email: %s", err)
		respondWithError(w, 401, "Incorrect email or password")
		return
	}
	err = auth.CheckPasswordHash(params.Password, dbUser.HashedPassword)
	if err != nil {
		log.Printf("user password not matching: %s", err)
		respondWithError(w, 401, "Incorrect email or password")
		return
	}
	type UserWithToken struct {
		ID           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
	}
	jwtToken, err := auth.MakeJWT(dbUser.ID, cfg.JWTSecret)
	if err != nil {
		log.Printf("error making JWT: %s", err)
		respondWithError(w, 500, "error making jwt")
		return
	}
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("error making refreshing token: %s", err)
		respondWithError(w, 500, "error making refresh token")
		return
	}
	// upload refresh token
	refreshTokenParams := database.CreateRefreshTokenParams{
		Token:  refreshToken,
		UserID: dbUser.ID,
	}
	_, err = cfg.DB.CreateRefreshToken(r.Context(), refreshTokenParams)
	if err != nil {
		log.Printf("error uploading refresh token: %s", err)
		respondWithError(w, 500, "error uploading refresh token")
		return
	}
	userWithoutPassword := UserWithToken{
		ID:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Email:        dbUser.Email,
		Token:        jwtToken,
		RefreshToken: refreshToken,
	}
	respondWithJSON(w, 200, userWithoutPassword)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("error getting bearer token %s", err)
		respondWithError(w, 401, "Unauthorized")
		return
	}
	dbToken, err := cfg.DB.GetRefreshToken(r.Context(), tokenString)
	if err != nil {
		log.Printf("error fetching token details: %s", err)
		respondWithError(w, 401, "token not found")
		return
	}
	if time.Now().After(dbToken.ExpiresAt) {
		respondWithError(w, 401, "Refresh Token Expired")
		return
	}
	if dbToken.RevokedAt.Valid {
		respondWithError(w, 401, "Refresh Token Revoked")
		return
	}
	jwtToken, err := auth.MakeJWT(dbToken.UserID, cfg.JWTSecret)
	if err != nil {
		log.Printf("error making jwt: %s", err)
		respondWithError(w, 500, "Internal server error")
		return
	}
	respondWithJSON(w, 200, map[string]string{
		"token": jwtToken,
	})
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("error getting bearer token %s", err)
		respondWithError(w, 401, "Unauthorized")
		return
	}
	err = cfg.DB.RevokeRefreshToken(r.Context(), tokenString)
	if err != nil {
		log.Printf("error revoking token: %s", err)
		respondWithError(w, 401, "refresh token not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) putUserHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("error getting bearer token %s", err)
		respondWithError(w, 401, "Unauthorized")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.JWTSecret)
	if err != nil {
		log.Printf("error validating: %s", err)
		respondWithError(w, 401, "Unauthorized")
		return
	}
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("error decoding parameters: %s", err)
		respondWithError(w, 400, "Something went wrong")
		return
	}
	params.Email = strings.TrimSpace(params.Email)
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("error hashing password: %s", err)
		respondWithError(w, 500, "internal server error")
		return
	}
	upParams := database.UpdateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
		ID:             userID,
	}
	updatedUser, err := cfg.DB.UpdateUser(r.Context(), upParams)
	if err != nil {
		log.Printf("error updating user: %s", err)
		respondWithError(w, 500, "error updating user: %s")
		return
	}
	type userResponse struct {
		ID        string    `json:"id"`
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	// Then before responding:
	response := userResponse{
		ID:        updatedUser.ID.String(),
		Email:     updatedUser.Email,
		CreatedAt: updatedUser.CreatedAt,
		UpdatedAt: updatedUser.UpdatedAt,
	}

	respondWithJSON(w, 200, response)
}

func (cfg *apiConfig) deleteChirpsByIdHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("error getting bearer token %s", err)
		respondWithError(w, 401, "Unauthorized")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.JWTSecret)
	if err != nil {
		log.Printf("error validating: %s", err)
		respondWithError(w, 401, "Unauthorized")
		return
	}
	chirpIDStr := r.PathValue("chirpID")

	// Convert string to UUID
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		// Handle invalid UUID
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}

	dbChirp, err := cfg.DB.GetChirpsById(r.Context(), chirpID)
	if err != nil {
		log.Printf("error fetching user by id %v", err)
		respondWithError(w, 404, "chirp not found")
		return
	}
	if userID != dbChirp.UserID {
		log.Printf("userid and chirp userid do not match %v", err)
		respondWithError(w, 403, "userid mismatch")
		return
	}
	err = cfg.DB.DeleteChirpsById(r.Context(), dbChirp.ID)
	if err != nil {
		log.Printf("error deleting chirp %v", err)
		respondWithError(w, 404, "chirp not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
