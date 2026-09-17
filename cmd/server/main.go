package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/juju/juju/permissions-demo/api"
	"github.com/juju/juju/permissions-demo/internal/httpapi"
	"github.com/juju/juju/permissions-demo/internal/openfga"
	"github.com/juju/juju/permissions-demo/internal/service"
	"github.com/juju/juju/permissions-demo/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	databasePath := env("DEMO_DATABASE", "./data/permissions-demo.db")
	data, err := store.Open(ctx, databasePath)
	if err != nil {
		log.Fatal(err)
	}
	defer data.Close()

	var engine *openfga.Engine
	for ctx.Err() == nil {
		engine, err = openfga.Bootstrap(ctx, env("OPENFGA_API_URL", "http://localhost:8080"), data)
		if err == nil {
			break
		}
		log.Printf("waiting for OpenFGA: %v", err)
		select {
		case <-ctx.Done():
			log.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
	}

	authorization := service.New(data, engine)
	if err := authorization.Sync(ctx); err != nil {
		log.Fatal(err)
	}
	implementation := httpapi.New(authorization)
	strict := api.NewStrictHandler(implementation, []api.StrictMiddlewareFunc{httpapi.DemoIdentityMiddleware})
	handler := api.HandlerWithOptions(strict, api.StdHTTPServerOptions{BaseURL: "/v1"})

	server := &http.Server{
		Addr:              env("DEMO_LISTEN", ":8088"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("permissions demo listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
