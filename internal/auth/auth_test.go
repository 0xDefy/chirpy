package auth

// import (
// 	"testing"
// 	"time"

// 	"github.com/google/uuid"
// )

// func TestMakeJWT(t *testing.T) {
// 	userID := uuid.New()
// 	tokenSecret := "supersecretkey"
// 	expiresIn := time.Hour

// 	token, err := MakeJWT(userID, tokenSecret, expiresIn)
// 	if err != nil {
// 		t.Fatalf("MakeJWT failed: %v", err)
// 	}

// 	if token == "" {
// 		t.Fatal("Generated token is empty")
// 	}
// }

// func TestValidateJWT(t *testing.T) {
// 	userID := uuid.New()
// 	tokenSecret := "supersecretkey"
// 	expiresIn := time.Hour

// 	// Create a JWT token
// 	token, err := MakeJWT(userID, tokenSecret, expiresIn)
// 	if err != nil {
// 		t.Fatalf("MakeJWT failed: %v", err)
// 	}

// 	// Validate the token
// 	parsedUserID, err := ValidateJWT(token, tokenSecret)
// 	if err != nil {
// 		t.Fatalf("ValidateJWT failed: %v", err)
// 	}

// 	if parsedUserID != userID {
// 		t.Errorf("Expected userID %v, got %v", userID, parsedUserID)
// 	}
// }

// func TestValidateJWT_InvalidToken(t *testing.T) {
// 	invalidToken := "invalid.token.here"
// 	tokenSecret := "supersecretkey"

// 	_, err := ValidateJWT(invalidToken, tokenSecret)
// 	if err == nil {
// 		t.Fatal("Expected an error for invalid token, but got nil")
// 	}
// }

// func TestValidateJWT_ExpiredToken(t *testing.T) {
// 	userID := uuid.New()
// 	tokenSecret := "supersecretkey"
// 	expiresIn := -time.Hour // Set an expiration in the past

// 	token, err := MakeJWT(userID, tokenSecret, expiresIn)
// 	if err != nil {
// 		t.Fatalf("MakeJWT failed: %v", err)
// 	}

// 	_, err = ValidateJWT(token, tokenSecret)
// 	if err == nil {
// 		t.Fatal("Expected an error for expired token, but got nil")
// 	}
// }
