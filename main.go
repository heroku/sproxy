package main

import (
	"log"
	"net/url"
	"time"

	"github.com/codegangsta/martini"
)

func main() {

	m := martini.Classic()

	pUrl, err := url.Parse("http://localhost:8000/")

	if err != nil {
		log.Fatal(err)
	}

	proxy := NewSingleHostReverseProxy(pUrl)
	proxy.FlushInterval = time.Millisecond * 100

	m.Get("/", proxy.ServeHTTP)
	m.Put("/", proxy.ServeHTTP)
	m.Post("/", proxy.ServeHTTP)
	m.Delete("/", proxy.ServeHTTP)
	m.Options("/", proxy.ServeHTTP)
	m.Run()

}
