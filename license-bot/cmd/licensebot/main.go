package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"kypaqet-license-bot/internal/httpapi"
	"kypaqet-license-bot/internal/store"
	"kypaqet-license-bot/internal/telegram"
)

func main() {
	var (
		botToken    = flag.String("bot-token", os.Getenv("BOT_TOKEN"), "Telegram bot token (or env BOT_TOKEN)")
		adminChatID = flag.String("admin-chat-id", getenvDefault("ADMIN_CHAT_ID", "1879326595"), "Admin chat id (or env ADMIN_CHAT_ID)")
		dbPath      = flag.String("db", getenvDefault("DB_PATH", "./data/licensebot.db"), "DB path (or env DB_PATH)")
		httpAddr    = flag.String("http", getenvDefault("HTTP_ADDR", ":8080"), "HTTP listen address (or env HTTP_ADDR)")
	)
	flag.Parse()

	if *botToken == "" {
		log.Fatal("BOT_TOKEN is required")
	}
	adminID, err := strconv.ParseInt(*adminChatID, 10, 64)
	if err != nil {
		log.Fatalf("invalid admin chat id: %v", err)
	}

	st, err := store.OpenBBolt(*dbPath)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	api := httpapi.New(st)
	httpServer := &http.Server{
		Addr:              *httpAddr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("http listening on %s", *httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http server error: %v", err)
			stop()
		}
	}()

	bot, err := telegram.NewBot(*botToken, adminID, st)
	if err != nil {
		log.Fatalf("telegram bot: %v", err)
	}
	go func() {
		if err := bot.Run(ctx); err != nil {
			log.Printf("bot error: %v", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

func getenvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
