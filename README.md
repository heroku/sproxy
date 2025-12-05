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

# Testing

## Running Tests Locally

To run the test suite locally:

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Run tests with coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Test Coverage

The test suite includes comprehensive tests for:

- **Email suffix validation** - Tests that only allowed email domains are accepted
- **HTTPS enforcement** - Tests that requests without `X-Forwarded-Proto: https` are redirected
- **Authorization middleware** - Tests session validation, expiration, and header injection
- **OAuth callback handling** - Tests state token validation and error handling
- **Health check bypass** - Tests that health check endpoints bypass authentication
- **Full authentication flow** - Tests complete end-to-end authentication and proxying

All tests use safe test data:
- Test email domains (`@example.com`, `@test.local`) - no internal domains
- Generated test secrets - no real credentials
- Mock backend servers - no external dependencies

## CI/CD

Tests run automatically on every push and pull request via GitHub Actions. The workflow:

1. Sets up Go 1.24
2. Verifies and downloads dependencies
3. Runs the full test suite
4. Generates coverage reports

See `.github/workflows/test.yml` for the complete workflow configuration.

FIXME: More info
