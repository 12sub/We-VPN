package handlers

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"
	"example.com/Web-VPN/internal/wireguard"

	"github.com/go-chi/chi/v5"
	"github.com/skip2/go-qrcode"
)

type DashboardHandler struct {
	wgManager *wireguard.Manager
	templates *template.Template
}

func NewDashboardHandler(wgManager *wireguard.Manager) *DashboardHandler {
	// 1. Define custom template functions
	funcMap := template.FuncMap{
		"formatBytes": func(bytes int64) string {
			const unit = 1024
			if bytes < unit {
				return fmt.Sprintf("%d B", bytes)
			}
			div, exp := int64(unit), 0
			for n := bytes / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
		},
	}

	// 2. Initialize template with FuncMap
	tmpl := template.New("").Funcs(funcMap)

	// 3. Parse all templates (Make sure you run the app from the root directory!)
	tmpl = template.Must(tmpl.ParseGlob("web/templates/*.html"))
	tmpl = template.Must(tmpl.ParseGlob("web/templates/partials/*.html"))

	return &DashboardHandler{
		wgManager: wgManager,
		templates: tmpl,
	}
}

func (h *DashboardHandler) ServeDashboard(w http.ResponseWriter, r *http.Request) {
	status, _ := h.wgManager.GetStatus()
	peers, _ := h.wgManager.GetPeers()
	stats, _ := h.wgManager.GetPeerStats(peers)

	// Merge stats
	for i := range peers {
		if s, ok := stats[peers[i].Name]; ok {
			peers[i].Endpoint = s.Endpoint
			if s.LatestHandshake.IsZero() {
				peers[i].LatestHandshake = "Never"
			} else {
				peers[i].LatestHandshake = time.Since(s.LatestHandshake).Round(time.Second).String() + " ago"
			}
			peers[i].TransferRX = s.TransferRX
			peers[i].TransferTX = s.TransferTX
		}
	}

	data := map[string]interface{}{
		"Status": status,
		"Peers":  peers,
	}

	// Check if it's an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		err := h.templates.ExecuteTemplate(w, "dashboard_content.html", data)
		if err != nil { log.Printf("HTMX Template Error: %v", err) }
		return
	}

	// Render full page
	err := h.templates.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		log.Printf("FATAL Template Error: %v", err)
		http.Error(w, "Template rendering failed. Check terminal.", http.StatusInternalServerError)
	}
}

func (h *DashboardHandler) GetAddPeerForm(w http.ResponseWriter, r *http.Request) {
	h.templates.ExecuteTemplate(w, "add_peer_form.html", nil)
}

func (h *DashboardHandler) PostAddPeer(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.FormValue("peer_name")
	if name == "" { http.Error(w, "Name required", http.StatusBadRequest); return }

	if err := h.wgManager.AddPeer(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError); return
	}
	h.GetPeerList(w, r)
}

func (h *DashboardHandler) GetPeerList(w http.ResponseWriter, r *http.Request) {
	peers, _ := h.wgManager.GetPeers()
	stats, _ := h.wgManager.GetPeerStats(peers)
	status, _ := h.wgManager.GetStatus()

	for i := range peers {
		if s, ok := stats[peers[i].Name]; ok {
			peers[i].Endpoint = s.Endpoint
			if s.LatestHandshake.IsZero() {
				peers[i].LatestHandshake = "Never"
			} else {
				peers[i].LatestHandshake = time.Since(s.LatestHandshake).Round(time.Second).String() + " ago"
			}
			peers[i].TransferRX = s.TransferRX
			peers[i].TransferTX = s.TransferTX
		}
	}

	data := map[string]interface{}{"Status": status, "Peers": peers}
	err := h.templates.ExecuteTemplate(w, "peer_list.html", data)
	if err != nil { log.Printf("Peer List Template Error: %v", err) }
}

func (h *DashboardHandler) DeletePeer(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.wgManager.DeletePeer(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError); return
	}
	h.GetPeerList(w, r)
}

func (h *DashboardHandler) DownloadConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	configStr, err := h.wgManager.GenerateClientConfig(name)
	if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.conf", name))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write([]byte(configStr))
}

func (h *DashboardHandler) TogglePeer(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.wgManager.TogglePeer(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError); return
	}
	h.GetPeerList(w, r)
}
var trafficHistory = []map[string]int64{}

func (h *DashboardHandler) GetTrafficAPI(w http.ResponseWriter, r *http.Request) {
	rx, tx, _ := h.wgManager.GetTotalTraffic()
	
	// Append to history (keep last 10)
	trafficHistory = append(trafficHistory, map[string]int64{"rx": rx, "tx": tx})
	if len(trafficHistory) > 10 {
		trafficHistory = trafficHistory[1:]
	}

	w.Header().Set("Content-Type", "application/json")
	// Simple JSON encoding without importing encoding/json to keep it brief, 
	// but in production, use json.Marshal!
	jsonStr := "["
	for i, pt := range trafficHistory {
		jsonStr += fmt.Sprintf(`{"rx":%d,"tx":%d}`, pt["rx"], pt["tx"])
		if i < len(trafficHistory)-1 { jsonStr += "," }
	}
	jsonStr += "]"
	w.Write([]byte(jsonStr))
}

func (h *DashboardHandler) ServerControl(w http.ResponseWriter, r *http.Request) {
	action := chi.URLParam(r, "action")
	var err error

	switch action {
	case "start":
		err = h.wgManager.StartService()
	case "stop":
		err = h.wgManager.StopService()
	case "restart":
		err = h.wgManager.RestartService()
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if err != nil {
		// Return HTMX error trigger
		w.Header().Set("HX-Trigger", `{"showError": "Failed to ` + action + ` service"}`)
		return
	}
	
	// Refresh the status bar
	h.GetPeerList(w, r) 
}

func (h *DashboardHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	logs, _ := h.wgManager.GetLogs()
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(logs))
}
func (h *DashboardHandler) GetQRCode(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	configStr, err := h.wgManager.GenerateClientConfig(name)
	if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }

	png, err := qrcode.Encode(configStr, qrcode.Medium, 256)
	if err != nil { http.Error(w, "QR fail", http.StatusInternalServerError); return }

	base64Img := base64.StdEncoding.EncodeToString(png)
	data := map[string]interface{}{"PeerName": name, "QRBase64": base64Img}
	
	err = h.templates.ExecuteTemplate(w, "qr_modal.html", data)
	if err != nil { log.Printf("QR Template Error: %v", err) }
}