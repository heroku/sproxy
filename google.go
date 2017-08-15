package main

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

const googleProfileURL = "https://www.googleapis.com/oauth2/v2/userinfo"

type googleProfile struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Link          string `json:"link"`
	Picture       string `json:"picture"`
	Gender        string `json:"gender"`
	Locale        string `json:"locale"`
	HD            string `json:"hd"`
}

func fetchGoogleProfile(ctx context.Context, t *oauth2.Token, o2c *oauth2.Config) (googleProfile, error) {
	var gp googleProfile
	r, err := o2c.Client(ctx, t).Get(googleProfileURL)
	if err != nil {
		return gp, errors.Wrap(err, "Fetching Google Profile")
	}
	d := json.NewDecoder(r.Body)
	err = d.Decode(&gp)
	r.Body.Close()
	return gp, errors.Wrap(err, "Unmarshaling Google Profile")
}
