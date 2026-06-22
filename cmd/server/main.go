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
	wgManager := wireguard.NewManager(cfg.WgConfigPath, cfg.WgInterface)
	dashHandler := handlers.NewDashboardHandler(wgManager)

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// Serve static files
	fileServer := http.FileServer(http.Dir("web/static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))

	// Routes
	r.Get("/", dashHandler.ServeDashboard)
	r.Get("/add-peer-form", dashHandler.GetAddPeerForm)
	r.Post("/add-peer", dashHandler.PostAddPeer)

	fmt.Printf("Server starting on http://localhost%s\n", cfg.Port)
	log.Fatal(http.ListenAndServe(cfg.Port, r))
}