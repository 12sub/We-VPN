package handlers

import (
	"net/http"
	"example.com/Web-VPN/internal/config"
)

type AuthHandler struct {
	Config *config.Config
}

func NewAuthHandler(cfg *config.Config) *AuthHandler {
	return &AuthHandler{Config: cfg}
}

// Middleware protects all routes except /login and /static
func (h *AuthHandler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" || r.URL.Path == "/logout" || 
		   r.URL.Path == "/static" || len(r.URL.Path) > 8 && r.URL.Path[:8] == "/static/" {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("session_token")
		if err != nil || cookie.Value != h.Config.SessionToken {
			// If it's an HTMX request, return 401 so HTMX can handle it, 
			// otherwise redirect.
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *AuthHandler) ServeLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		http.ServeFile(w, r, "web/templates/login.html")
		return
	}

	// POST: Handle login
	r.ParseForm()
	user := r.FormValue("username")
	pass := r.FormValue("password")

	if user == h.Config.AdminUser && pass == h.Config.AdminPass {
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    h.Config.SessionToken,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400 * 7, // 1 week
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Failed login
	http.ServeFile(w, r, "web/templates/login.html") // In a real app, pass an error message
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}