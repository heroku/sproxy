package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-martini/martini"
	"github.com/joeshaw/envdecode"
	"github.com/martini-contrib/sessions"
	"github.com/tomsteele/dmv"
)

type config struct {
	clientID              string `env:"CLIENT_ID,required"`                                       // Google Client ID
	clientSecret          string `env:"CLIENT_SECRET,required"`                                   // Google Client Secret
	sessionSecret         string `env:"SESSION_SECRET,required"`                                  // Random session auth key
	sessionEncrypttionKey string `env:"SESSION_ENCRYPTION_KEY,required"`                          // Random session encryption key
	dnsName               string `env:"DNS_NAME,required"`                                        // Public facing DNS Hostname
	cookieMaxAge          int    `env:"COOKIE_MAX_AGE,default=1440"`                              // Cookie MaxAge, Defaults to 1 day
	cookieName            string `env:"COOKIE_NAME,default=sproxy_session"`                       // The name of the cookie
	proxyURL              string `env:"PROXY_URL,default=http://localhost:8000/"`                 // URL to Proxy to
	callBackPath          string `env:"CALLBACK_PATH,default=/auth/callback/google"`              // Callback URL
	authPath              string `env:"AUTH_PATH,default=/auth/google"`                           // Auth Path
	healthCheckPath       string `env:"HEALTH_CHECK_PATH,default=/en-US/static/html/credit.html"` // Health Check path in splunk, this path is proxied w/o auth. The default is a static file served by the splunk web server
	emailSuffix           string `env:"EMAIL_SUFFIX,default=@heroku.com"`                         // Required email suffix. Emails w/o this suffix will not be let in
}

var (
	cfg            = config{}
	oAuthScopes    = []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}
	sessionOptions = sessions.Options{Secure: true, HttpOnly: true}
)

// Authorize the user based on email and a set OpenIDUser
func authorize(s sessions.Session, w http.ResponseWriter, r *http.Request) {
	email := s.Get("email")
	if email == nil || !strings.HasSuffix(email.(string), cfg.emailSuffix) {
		http.Redirect(w, r, cfg.authPath, http.StatusFound)
		return
	}

	openIDUser := s.Get("OpenIDUser")
	if openIDUser != nil && openIDUser != "" {
		r.Header.Set("X-Openid-User", openIDUser.(string))
	} else {
		// No openIDUser set, so abort and restart the auth flow
		http.Redirect(w, r, cfg.authPath, http.StatusFound)
	}
}

// Set the OpenIDUser and other session values based on the data from Google
func handleCallback(goog *dmv.Google, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	// Handle any errors.
	if len(goog.Errors) > 0 {
		http.Error(w, "Oauth failure", http.StatusInternalServerError)
		return
	}

	s.Set("GoogleID", goog.Profile.ID)
	s.Set("email", goog.Profile.Email)

	parts := strings.SplitN(goog.Profile.Email, "@", 2)
	if len(parts) < 2 {
		http.Error(w, "Unable to determine OpenIDUser from email `"+goog.Profile.Email+"`", http.StatusInternalServerError)
		return
	}
	s.Set("OpenIDUser", strings.ToLower(parts[0]))

	http.Redirect(w, r, "/", http.StatusFound)
}

// Ensure that we're being proxied to ourselves via https
func enforceXForwardedProto(w http.ResponseWriter, r *http.Request) {
	xff := r.Header.Get("X-Forwarded-Proto")
	if xff != "https" {
		u := new(url.URL)
		*u = *r.URL
		u.Scheme = "https"
		if u.Host == "" {
			u.Host = r.Host
		}

		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}

func main() {
	err := envdecode.Decode(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	switch len([]byte(cfg.sessionEncrypttionKey)) {
	case 16, 24, 32:
	default:
		log.Fatal("Length of SESSION_ENCRYPTION_KEY is not 16, 24 or 32")
	}

	sessionOptions.MaxAge = cfg.cookieMaxAge

	googleOpts := &dmv.OAuth2Options{
		ClientID:     cfg.clientID,
		ClientSecret: cfg.clientSecret,
		RedirectURL:  "https://" + cfg.dnsName + cfg.callBackPath,
		Scopes:       oAuthScopes,
	}

	m := martini.Classic()

	pURL, err := url.Parse(cfg.proxyURL)

	if err != nil {
		log.Fatal(err)
	}

	store := sessions.NewCookieStore(
		[]byte(cfg.sessionSecret),
		[]byte(cfg.sessionEncrypttionKey),
	)

	// Inject a session when it's needed
	m.Use(sessions.Sessions(cfg.cookieName, store))

	proxy := httputil.NewSingleHostReverseProxy(pURL)

	// Health Check URL, so just proxy w/o any processing
	m.Get(cfg.healthCheckPath, proxy.ServeHTTP)

	// Google Auth
	m.Get(cfg.authPath, dmv.AuthGoogle(googleOpts))
	m.Get(cfg.callBackPath, dmv.AuthGoogle(googleOpts), handleCallback)

	// Proxy the rest
	m.Get("/**", enforceXForwardedProto, authorize, proxy.ServeHTTP)
	m.Put("/**", enforceXForwardedProto, authorize, proxy.ServeHTTP)
	m.Post("/**", enforceXForwardedProto, authorize, proxy.ServeHTTP)
	m.Delete("/**", enforceXForwardedProto, authorize, proxy.ServeHTTP)
	m.Options("/**", enforceXForwardedProto, authorize, proxy.ServeHTTP)
	m.Run()
}
