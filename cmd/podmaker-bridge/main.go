// Command podmaker-bridge is a tiny local-only HTTP daemon that
// exposes the user's locally installed credential CLIs (aws-vault
// today; more to come) to the PodMaker web app over a CORS-locked
// loopback endpoint.
//
// Default address is 127.0.0.1:7766. The SaaS UI fetches this from
// the browser when the user opts in to "Use local vault" during
// cloud-account creation.
//
// Install (dev):
//
//	go install podmaker.sh/apps/podmaker-bridge/cmd/podmaker-bridge@latest
//	podmaker-bridge
//
// Configuration via environment:
//
//	PODMAKER_BRIDGE_ADDR      (default 127.0.0.1:7766)
//	PODMAKER_BRIDGE_ORIGINS   (comma-separated; default https://podmaker.test,http://podmaker.test)
//	PODMAKER_BRIDGE_TOKEN     (optional; if set, all write endpoints require Authorization: Bearer <token>)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"podmaker.sh/apps/podmaker-bridge/internal/api"
)

const version = "0.0.1-dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	addr := envOr("PODMAKER_BRIDGE_ADDR", "127.0.0.1:7766")
	origins := envOr("PODMAKER_BRIDGE_ORIGINS", "https://panel.podmaker.test,https://podmaker.test,http://podmaker.test,https://panel.podmaker.sh,https://app.podmaker.sh,https://localhost:3000")
	token := os.Getenv("PODMAKER_BRIDGE_TOKEN")

	cfg := api.Config{
		AllowedOrigins: splitCSV(origins),
		BearerToken:    token,
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           api.New(cfg).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("podmaker-bridge listening",
			"version", version,
			"addr", addr,
			"origins", cfg.AllowedOrigins,
			"auth", token != "",
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
