package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/bounce"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/mail"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/server"
)

// Set by the build: -ldflags "-X main.version=..."
var version = "dev"

const defaultConfig = "/etc/gatekeeper/config.json"

func main() {
	command := "serve"
	args := os.Args[1:]
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		command, args = args[0], args[1:]
	}
	var err error
	switch command {
	case "serve":
		err = serve(args)
	case "check":
		err = check(args)
	case "healthcheck":
		err = healthcheck(args)
	case "version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("unknown command %q - serve, check, healthcheck or version", command)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func configFlag(name string, args []string) (string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	path := flags.String("config", envOr("GATEKEEPER_CONFIG", defaultConfig), "configuration file")
	return *path, flags.Parse(args)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func check(args []string) error {
	path, err := configFlag("check", args)
	if err != nil {
		return err
	}
	if _, err := config.Load(path); err != nil {
		return err
	}
	fmt.Println("configuration ok")
	return nil
}

func healthcheck(args []string) error {
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	address := flags.String("addr", "127.0.0.1:8081", "health listener")
	if err := flags.Parse(args); err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + *address + "/healthz")
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health check answered %d", response.StatusCode)
	}
	return nil
}

func serve(args []string) error {
	path, err := configFlag("serve", args)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	options := server.Options{Log: log}
	if cfg.Mail != nil {
		var tracker *bounce.Tracker
		if b := cfg.Mail.Bounces; b != nil {
			tracker = bounce.NewTracker(cfg.Mail.From, b.Suppress.D(), 100_000)
			go bounce.NewPoller(cfg.Mail, tracker, log).Run(ctx)
		}
		queue := mail.NewQueue(cfg, mail.NewSender(cfg.Mail), tracker, log)
		go queue.Run(ctx)
		options.Mailer = queue
	}
	gate := server.New(cfg, options)
	go gate.Janitor(ctx)

	public := &http.Server{
		Addr:              cfg.Listen,
		Handler:           gate.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	health := &http.Server{
		Addr: cfg.HealthListen,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte("ok\n"))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	failed := make(chan error, 2)
	for _, srv := range []*http.Server{public, health} {
		go func() {
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				failed <- err
			}
		}()
	}
	log.Info("gatekeeper started", "version", version, "listen", cfg.Listen, "hosts", len(cfg.Hosts), "providers", len(cfg.Providers),
		"email", cfg.Mail != nil, "bounces", cfg.Mail != nil && cfg.Mail.Bounces != nil, "altcha", cfg.Altcha != nil)

	select {
	case err = <-failed:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if stopped := errors.Join(public.Shutdown(shutdown), health.Shutdown(shutdown)); stopped != nil {
		log.Warn("shutdown incomplete", "error", stopped)
	}
	log.Info("gatekeeper stopped")
	return err
}
