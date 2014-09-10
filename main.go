package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/go-martini/martini"
	"github.com/martini-contrib/sessions"

	"github.com/tomsteele/dmv"

	"github.com/boltdb/bolt"
	"github.com/yosssi/boltstore/reaper"
	bstore "github.com/yosssi/boltstore/store"
)

var (
	clientId      = os.Getenv("CLIENT_ID")
	clientSecret  = os.Getenv("CLIENT_SECRET")
	sessionSecret = os.Getenv("SESSION_SECRET")
	db            *bolt.DB
)

func authorize(s sessions.Session, rw http.ResponseWriter, req *http.Request) {
	email := s.Get("email")
	if email == nil || !strings.HasSuffix(email.(string), "@heroku.com") {
		http.Redirect(rw, req, "/auth/google", http.StatusFound)
		return
	}
}

func enforceXForwardedProto(rw http.ResponseWriter, req *http.Request) {
	xff := req.Header.Get("X-Forwarded-Proto")
	if xff != "https" {
		u := new(url.URL)
		*u = *req.URL
		u.Scheme = "https"
		if u.Host == "" {
			u.Host = req.Host
		}

		http.Redirect(rw, req, u.String(), http.StatusFound)
	}
}

func main() {

	googleOpts := &dmv.OAuth2Options{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  "https://splunk-searcher.ssl.edward.herokudev.com/auth/callback/google",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
	}

	db, err := bolt.Open("./sessions.db", 0666, nil)
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()
	defer reaper.Quit(reaper.Run(db, reaper.Options{}))

	m := martini.Classic()

	pUrl, err := url.Parse("http://localhost:8000/")

	if err != nil {
		log.Fatal(err)
	}

	proxy := NewSingleHostReverseProxy(pUrl)

	store, err := bstore.New(db, bstore.Config{}, []byte(sessionSecret))
	if err != nil {
		log.Fatal(err)
	}

	m.Use(sessions.Sessions("sproxy_session", store))

	// Health Check URL, so just proxy w/o anything
	m.Get("/en-US/static/html/status.html", proxy.ServeHTTP)

	// Google Auth
	m.Get("/auth/google", dmv.AuthGoogle(googleOpts))

	m.Get("/auth/callback/google", dmv.AuthGoogle(googleOpts), func(goog *dmv.Google, s sessions.Session, rw http.ResponseWriter, req *http.Request) {
		// Handle any errors.
		if len(goog.Errors) > 0 {
			http.Error(rw, "Oauth failure", http.StatusInternalServerError)
			return
		}

		fmt.Printf("CALLBACK: %+v\n", goog)
		s.Set("email", goog.Profile.Email)
		http.Redirect(rw, req, "/", http.StatusFound)
	})

	// Proxy the rest
	m.Get("/**", enforceXForwardedProto, authorize, proxy.ServeHTTP)
	m.Put("/**", enforceXForwardedProto, authorize, proxy.ServeHTTP)
	m.Post("/**", enforceXForwardedProto, authorize, proxy.ServeHTTP)
	m.Delete("/**", enforceXForwardedProto, authorize, proxy.ServeHTTP)
	m.Options("/**", enforceXForwardedProto, authorize, proxy.ServeHTTP)
	m.Run()
}
