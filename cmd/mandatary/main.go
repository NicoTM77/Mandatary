// Mandatary currently runs a loopback-only static development skeleton.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/NicoTM77/Mandatary/web"
)

func developmentServer() *http.Server {
	return &http.Server{
		Addr:              "127.0.0.1:8080",
		Handler:           web.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
}

func main() {
	repository, err := openRepository(context.Background(), os.Getenv)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	defer func() {
		if err := repository.Close(); err != nil {
			log.Print(err)
		}
	}()
	log.Print("Mandatary development skeleton: http://127.0.0.1:8080 (no product APIs)")
	if err := developmentServer().ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
