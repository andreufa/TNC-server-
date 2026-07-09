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

	"tnc-server/internal/config"
	"tnc-server/internal/db"
	"tnc-server/internal/hub"
	"tnc-server/internal/store"
	"tnc-server/internal/tcp"
	"tnc-server/internal/web"
)

func main() {
	// // --- ОТЛАДКА: Проверяем, что видит программа ---
	// cwd, _ := filepath.Abs(".")
	// log.Printf("[DEBUG] Working directory: %s", cwd)

	// checkFile := func(name string) {
	// 	_, err := os.Stat(name)
	// 	if err == nil {
	// 		log.Printf("[DEBUG] ✅ File found: %s", name)
	// 		data, _ := os.ReadFile(name)
	// 		log.Printf("[DEBUG] Content of %s:\n%s", name, string(data))
	// 	} else {
	// 		log.Printf("[DEBUG] ❌ File NOT found: %s (error: %v)", name, err)
	// 	}
	// }

	// checkFile(".env.local")
	// checkFile(".env")
	// // -----------------------------------------------
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx := context.Background()

	// --- database ---
	pool, err := db.Connect(ctx, cfg.DatabaseURL())
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool, "migrations"); err != nil {
		return err
	}
	log.Print("db: migrations applied")

	// --- stores ---
	devices := store.NewDeviceStore(pool)
	users := store.NewUserStore(pool)
	sessions := store.NewSessionStore(pool)

	if err := users.EnsureBootstrap(ctx, cfg.BootstrapAdminUser, cfg.BootstrapAdminPass); err != nil {
		return err
	}
	log.Printf("users: bootstrap admin %q ensured", cfg.BootstrapAdminUser)

	// periodic session cleanup
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			if err := sessions.CleanupExpired(context.Background()); err != nil {
				log.Printf("sessions: cleanup error: %v", err)
			}
		}
	}()

	// --- hub ---
	h := hub.New()
	go h.Run()
	defer h.Stop()

	// --- TCP server ---
	tcpSrv := tcp.NewServer(cfg.TCPAddr, devices, h)
	tcpErr := make(chan error, 1)
	go func() { tcpErr <- tcpSrv.ListenAndServe() }()

	// --- HTTP server ---
	webSrv, err := web.NewServer(devices, users, sessions)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: webSrv.Handler(),
	}
	httpErr := make(chan error, 1)
	go func() {
		log.Printf("http: listening on %s", cfg.HTTPAddr)
		httpErr <- httpSrv.ListenAndServe()
	}()

	// --- wait for signal or fatal error ---
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case <-stop:
		log.Print("shutdown: signal received")
	case err := <-tcpErr:
		if err != nil {
			log.Printf("tcp: server error: %v", err)
		}
	case err := <-httpErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http: server error: %v", err)
		}
	}

	// --- graceful shutdown ---
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("http: shutdown error: %v", err)
	}
	tcpSrv.Shutdown()
	log.Print("shutdown: complete")
	return nil
}
