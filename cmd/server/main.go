package main

import (
	"fmt"
	"log"
	"net/http"
	"example.com/Web-VPN/internal/config"
	"example.com/Web-VPN/internal/handlers"
	"example.com/Web-VPN/internal/wireguard"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	cfg := config.Load()
	wgManager := wireguard.NewManager(cfg)
	dashHandler := handlers.NewDashboardHandler(wgManager)
	authHandler := handlers.NewAuthHandler(cfg)

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// Apply Auth Middleware to all subsequent routes
	r.Use(authHandler.Middleware)

	// Serve static files
	fileServer := http.FileServer(http.Dir("web/static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))

	// Auth Routes
	r.Get("/login", authHandler.ServeLogin)
	r.Post("/login", authHandler.ServeLogin)
	r.Get("/logout", authHandler.Logout)

	// Routes
	r.Get("/", dashHandler.ServeDashboard)
	r.Get("/add-peer-form", dashHandler.GetAddPeerForm)
	r.Post("/add-peer", dashHandler.PostAddPeer)

	// Phase 2 Routes
	r.Get("/peer-list", dashHandler.GetPeerList)
	r.Delete("/peer/{name}", dashHandler.DeletePeer)
	r.Get("/peer/{name}/download", dashHandler.DownloadConfig)

	// Phase 3 Routes
	r.Post("/peer/{name}/toggle", dashHandler.TogglePeer)
	r.Get("/peer/{name}/qr", dashHandler.GetQRCode)

	fmt.Printf("Server starting on http://localhost%s\n", cfg.Port)
	log.Fatal(http.ListenAndServe(cfg.Port, r))
}