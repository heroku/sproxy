# What

Proxy designed to sit on a splunk searcher head, but behind an ELB (or other https terminating proxy), to handle the Google OAuth 2.0 flow.

# Config Vars

See the Config struct for required and optional config vars and their defaults

# Google Setup

* Log into: https://console.developers.google.com
* Create a project.
* Under "APIs & Auth", click "Credentials"
* Under "OAuth", click "Create new Client ID"
* Leave the "Application Type" set to "Web application"
* Under "Authorized Javascript Origins" enter: `https://<the.host.domain>`
* Under "Authorized Redirect URL" enter: `https://<the.host.domain>/auth/callback/google`
* Click "Create Client ID"
* Under "APIs & Auth", click "Consent screen"
* Enter your/an email address, Product Name, click "Save". What you enter here will appear on the Google OAuth pages when authenticating.


FIXME: More info