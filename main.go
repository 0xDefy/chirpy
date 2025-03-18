package main

import (
	// "fmt"
	"log"
	"net/http"
)

func main() {
	serveMux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("error listening and serving: %v", err)
	}
}
