package handlers

import (
	"html/template"
	"net/http"
	// "path/filepath"
	"example.com/Web-VPN/internal/wireguard"
)

type DashboardHandler struct {
	wgManager *wireguard.Manager
	templates *template.Template
}

func NewDashboardHandler(wgManager *wireguard.Manager) *DashboardHandler {
	// Parse all templates
	tmpl := template.Must(template.ParseGlob("web/templates/*.html"))
	template.Must(tmpl.ParseGlob("web/templates/partials/*.html"))
	
	return &DashboardHandler{
		wgManager: wgManager,
		templates: tmpl,
	}
}

func (h *DashboardHandler) ServeDashboard(w http.ResponseWriter, r *http.Request) {
	status, _ := h.wgManager.GetStatus()
	peers, _ := h.wgManager.GetPeers()

	data := map[string]interface{}{
		"Status": status,
		"Peers":  peers,
	}

	// Check if it's an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		h.templates.ExecuteTemplate(w, "dashboard_content.html", data)
		return
	}

	h.templates.ExecuteTemplate(w, "base.html", data)
}

func (h *DashboardHandler) GetAddPeerForm(w http.ResponseWriter, r *http.Request) {
	h.templates.ExecuteTemplate(w, "add_peer_form.html", nil)
}

func (h *DashboardHandler) PostAddPeer(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.FormValue("peer_name")
	
	if name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	err := h.wgManager.AddPeer(name)
	if err != nil {
		http.Error(w, "Failed to add peer: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the updated peer list for HTMX to swap
	peers, _ := h.wgManager.GetPeers()
	status, _ := h.wgManager.GetStatus()
	
	data := map[string]interface{}{
		"Status": status,
		"Peers":  peers,
	}
	h.templates.ExecuteTemplate(w, "peer_list.html", data)
}