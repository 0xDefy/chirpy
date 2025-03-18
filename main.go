package main

import (
	// "fmt"
	"log"
	"net/http"
)

func main() {
	serveMux := http.NewServeMux()
	serveMux.Handle("/app/",
		http.StripPrefix("/app/", http.FileServer(http.Dir("."))))
	serveMux.HandleFunc("/healthz", healthzHandle)
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
