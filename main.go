package main

import (
	"fmt"
	"net/http"
)

type Server struct {
	Addr    string
	Handler http.ServeMux
}

func main() {
	serveMux := http.NewServeMux()
	newServer := Server{
		Addr:    ":8080",
		Handler: *serveMux,
	}
	err := http.ListenAndServe(newServer.Addr, &newServer.Handler)
	if err != nil {
		fmt.Errorf("error listening and serving: %w", err)
	}
}
