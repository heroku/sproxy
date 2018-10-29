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

type configuration struct {
	ClientID              string   `env:"CLIENT_ID,required"`                                       // Google Client ID
	ClientSecret          string   `env:"CLIENT_SECRET,required"`                                   // Google Client Secret
	SessionSecret         string   `env:"SESSION_SECRET,required"`                                  // Random session auth key
	SessionEncrypttionKey string   `env:"SESSION_ENCRYPTION_KEY,required"`                          // Random session encryption key
	CookieMaxAge          int      `env:"COOKIE_MAX_AGE,default=1440"`                              // Cookie MaxAge, Defaults to 1 day
	CookieName            string   `env:"COOKIE_NAME,default=sproxy_session"`                       // The name of the cookie
	ProxyURL              *url.URL `env:"PROXY_URL,default=http://localhost:8000/"`                 // URL to Proxy to
	CallbackPath          string   `env:"CALLBACK_PATH,default=/auth/callback/google"`              // Callback URL
	HealthCheckPath       string   `env:"HEALTH_CHECK_PATH,default=/en-US/static/html/credit.html"` // Health Check path in splunk, this path is proxied w/o auth. The default is a static file served by the splunk web server
	EmailSuffix           string   `env:"EMAIL_SUFFIX,default=@heroku.com"`                         // Required email suffix. Emails w/o this suffix will not be let in
	StateToken            string   `env:"STATE_TOKEN,required"`                                     // Token used when communicating with Google Oauth2 provider
}

var config configuration

func newOauth2Config(host string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  "https://" + host + config.CallbackPath,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
}

// Authorize the user based on the email stored in the named session and matching the suffix. If the email doesn't exist
// in the session or if the 'OpenIDUser' isn't set in the session, then redirect, otherwise set the X-Openid-User
// header to what was stored in the session.
func authorize(s sessions.Store, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logPrefix := fmt.Sprintf("app=sproxy fn=authorize method=%s path=%s\n",
			r.Method, r.URL.Path)

		session, err := s.Get(r, config.CookieName)
		if err != nil {
			log.Printf("%s auth=failed error=%q\n", logPrefix, err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		o2c := newOauth2Config(r.Host)

		redirect := o2c.AuthCodeURL(config.StateToken, oauth2.AccessTypeOnline)

		session.Values["return_to"] = r.URL.RequestURI()
		session.Save(r, w)

		email, ok := session.Values["email"]
		if !ok || email == nil || !strings.HasSuffix(email.(string), config.EmailSuffix) {
			if email == nil {
				email = ""
			}
			log.Printf("%s auth=failed missing=Email email=%s redirect=%s\n", logPrefix, email.(string), redirect)
			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
			return
		}

		openIDUser, ok := session.Values["OpenIDUser"]
		if !ok || openIDUser == nil {
			if openIDUser == nil {
				openIDUser = ""
			}
			log.Printf("%s auth=failed missing=OpenIDUser user=%s redirect=%s\n", logPrefix, openIDUser.(string), redirect)
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
func handleGoogleCallback(s sessions.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logPrefix := fmt.Sprintf("app=sproxy fn=callback method=%s path=%s\n",
			r.Method, r.URL.Path)

		o2c := newOauth2Config(r.Host)

		if v := r.FormValue("state"); v != config.StateToken {
			log.Printf("%s callback=failed error=%s\n", logPrefix, fmt.Sprintf("Bad state token: %s", v))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		ctx := context.Background()
		t, err := o2c.Exchange(r.Context(), r.FormValue("code"))
		if err != nil {
			log.Printf("%s callback=failed error=%s\n", logPrefix, err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gp, err := fetchGoogleProfile(ctx, t, o2c)
		if err != nil {
			log.Printf("%s %s\n", logPrefix, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if gp.Email == "" || !strings.HasSuffix(gp.Email, config.EmailSuffix) {
			err := fmt.Errorf("Invalid Google Profile Email: %q", gp.Email)
			log.Printf("%s callback=failed error=%s\n", logPrefix, err.Error())
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		session, err := s.Get(r, config.CookieName)
		if err != nil {
			log.Printf("%s callback=failed error=%s\n", logPrefix, err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		session.Values["email"] = gp.Email
		session.Values["GoogleID"] = gp.ID

		parts := strings.SplitN(gp.Email, "@", 2)
		if len(parts) < 2 {
			err := fmt.Errorf("Unable to determine OpenIDUser from email %q", gp.Email)
			log.Printf("%s callback=failed error=%s\n", logPrefix, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Values["OpenIDUser"] = strings.ToLower(parts[0])
		target, ok := session.Values["return_to"].(string)
		if !ok {
			target = "/"
		}

		if err := session.Save(r, w); err != nil {
			log.Printf("%s callback=failed error=%s\n", logPrefix, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("%s callback=successful\n", logPrefix)
		http.Redirect(w, r, target, http.StatusFound)
	})
}

func main() {
	if err := envdecode.Decode(&config); err != nil {
		log.Fatal(err)
	}

	switch len(config.SessionEncrypttionKey) {
	case 16, 24, 32:
	default:
		log.Fatal("Length of SESSION_ENCRYPTION_KEY is not 16, 24 or 32")
	}

	store := sessions.NewCookieStore([]byte(config.SessionSecret), []byte(config.SessionEncrypttionKey))
	store.Options.MaxAge = config.CookieMaxAge
	store.Options.Secure = true

	proxy := httputil.NewSingleHostReverseProxy(config.ProxyURL)

	// Handle Google Callback
	http.Handle(config.CallbackPath, handleGoogleCallback(store))

	// Health Check
	http.Handle(config.HealthCheckPath, proxy)

	// Base HTTP Request handler
	http.Handle("/", enforceXForwardedProto(authorize(store, proxy)))

	host := os.Getenv("HOST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	listen := host + ":" + port
	log.Println("Listening on", listen)

	log.Fatal(http.ListenAndServe(listen, nil))
}
