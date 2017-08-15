package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/joeshaw/envdecode"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type config struct {
	clientID              string   `env:"CLIENT_ID,required"`                                       // Google Client ID
	clientSecret          string   `env:"CLIENT_SECRET,required"`                                   // Google Client Secret
	sessionSecret         string   `env:"SESSION_SECRET,required"`                                  // Random session auth key
	sessionEncrypttionKey string   `env:"SESSION_ENCRYPTION_KEY,required"`                          // Random session encryption key
	dnsName               string   `env:"DNS_NAME,required"`                                        // Public facing DNS Hostname
	cookieMaxAge          int      `env:"COOKIE_MAX_AGE,default=1440"`                              // Cookie MaxAge, Defaults to 1 day
	cookieName            string   `env:"COOKIE_NAME,default=sproxy_session"`                       // The name of the cookie
	proxyURL              *url.URL `env:"PROXY_URL,default=http://localhost:8000/"`                 // URL to Proxy to
	callbackPath          string   `env:"CALLBACK_PATH,default=/auth/callback/google"`              // Callback URL
	healthCheckPath       string   `env:"HEALTH_CHECK_PATH,default=/en-US/static/html/credit.html"` // Health Check path in splunk, this path is proxied w/o auth. The default is a static file served by the splunk web server
	emailSuffix           string   `env:"EMAIL_SUFFIX,default=@heroku.com"`                         // Required email suffix. Emails w/o this suffix will not be let in
	stateToken            string   `env:"STATE_TOKEN,required"`                                     // Token used when communicating with Google Oauth2 provider
}

// Authorize the user based on the email stored in the named session and matching the suffix. If the email doesn't exist
// in the session or if the 'OpenIDUser' isn't set in the session, then redirect, otherwise set the X-Openid-User
// header to what was stored in the session.
func authorize(name, suffix, redirect string, s sessions.Store, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.Get(r, name)
		if err != nil {
			log.Printf("error getting session: %q\n", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if email, ok := session.Values["email"]; !ok || email == nil || !strings.HasSuffix(email.(string), suffix) {
			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
			return
		}
		openIDUser, ok := session.Values["OpenIDUser"]
		if !ok || openIDUser == nil {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		r.Header.Set("X-Openid-User", openIDUser.(string))
		h.ServeHTTP(w, r)
	})
}

// enforceXForwardedProto header is set before processing the handler.
// If it's not then redirect to the https version of the URL.
func enforceXForwardedProto(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xff := r.Header.Get("X-Forwarded-Proto")
		if xff == "https" {
			h.ServeHTTP(w, r)
			return
		}

		u := new(url.URL)
		*u = *r.URL
		u.Scheme = "https"
		if u.Host == "" {
			u.Host = r.Host
		}

		http.Redirect(w, r, u.String(), http.StatusFound)
	})
}

// Set the OpenIDUser and other session values based on the data from Google
func handleGoogleCallback(token, name, suffix string, o2c *oauth2.Config, s sessions.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.FormValue("state"); v != token {
			log.Printf("Bad state token %q\n", v)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		ctx := context.Background()
		t, err := o2c.Exchange(r.Context(), r.FormValue("code"))
		if err != nil {
			log.Printf("Error during oauth exchange: %s\n", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gp, err := fetchGoogleProfile(ctx, t, o2c)
		if err != nil {
			log.Println(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if gp.Email == "" || !strings.HasSuffix(gp.Email, suffix) {
			err := fmt.Errorf("Invalid Google Profile Email: %q", gp.Email)
			log.Println(err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		session, err := s.Get(r, name)
		if err != nil {
			log.Printf("error getting session: %q\n", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		session.Values["email"] = gp.Email
		session.Values["GoogleID"] = gp.ID

		parts := strings.SplitN(gp.Email, "@", 2)
		if len(parts) < 2 {
			err := fmt.Errorf("Unable to determine OpenIDUser from email %q", gp.Email)
			log.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session.Values["OpenIDUser"] = strings.ToLower(parts[0])

		if err := session.Save(r, w); err != nil {
			log.Printf("Error Saving Session: %q\n", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func main() {
	var cfg config
	if err := envdecode.Decode(&cfg); err != nil {
		log.Fatal(err)
	}

	switch len(cfg.sessionEncrypttionKey) {
	case 16, 24, 32:
	default:
		log.Fatal("Length of SESSION_ENCRYPTION_KEY is not 16, 24 or 32")
	}

	o2c := &oauth2.Config{
		ClientID:     cfg.clientID,
		ClientSecret: cfg.clientSecret,
		RedirectURL:  "https://" + cfg.dnsName + cfg.callbackPath,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}

	store := sessions.NewCookieStore([]byte(cfg.sessionSecret), []byte(cfg.sessionEncrypttionKey))
	store.Options.MaxAge = cfg.cookieMaxAge
	store.Options.Secure = true

	http.Handle(cfg.callbackPath,
		handleGoogleCallback(
			cfg.stateToken, cfg.cookieName, cfg.emailSuffix,
			o2c,
			store,
		),
	)

	proxy := httputil.NewSingleHostReverseProxy(cfg.proxyURL)
	http.Handle(cfg.healthCheckPath, proxy)
	http.Handle("/",
		enforceXForwardedProto(
			authorize(
				cfg.cookieName, cfg.emailSuffix, o2c.AuthCodeURL(cfg.stateToken, oauth2.AccessTypeOnline),
				store,
				proxy,
			),
		),
	)

	// Here to emulate martini classic
	host := os.Getenv("HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	http.ListenAndServe(host+":"+port, nil)
}
