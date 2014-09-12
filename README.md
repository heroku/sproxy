# What

Proxy designed to sit on a splunk searcher head, but behind an ELB (or other https terminating proxy), to handle the Google OAuth 2.0 flow.

Assumes that splunk usernames are the same as the part of your authentication email address before the @.

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

# What about first Login?

* visit "https://**the.host.domain**", do the oauth dance and then visit "https://**the.host.domain**/en-US/account/logout" and enter the default admin user/password so you can log into the UI and setup your users.

FIXME: More info
