# Sproxy API

This document describes the externally visible behavior of `sproxy` as implemented today.

## Overview

`sproxy` is an auth-gating reverse proxy:

- It handles Google OAuth callback login.
- It validates session state on protected routes.
- It forwards allowed requests to the configured upstream service (`PROXY_URL`).

## Configuration-Driven Endpoints

Routes are configurable through environment variables. Defaults below reflect current code defaults.

- `CALLBACK_PATH` (default: `/auth/callback/google`)
- `HEALTH_CHECK_PATH` (default: `/en-US/static/html/credit.html`)

## Service Endpoints

### `ANY {CALLBACK_PATH}` (default: `/auth/callback/google`)

OAuth callback endpoint used after Google sign-in.

#### Query parameters

- `state` (required): must match `STATE_TOKEN`
- `code` (required): OAuth authorization code

#### Behavior

- If `state` mismatches, returns `400 Bad Request`.
- Exchanges `code` for an OAuth token using Google OAuth.
- Fetches Google profile from Google userinfo API.
- Validates profile email against `EMAIL_SUFFIX` allow-list.
- Creates/updates session values:
  - `email`
  - `GoogleID`
  - `OpenIDUser` (email local-part, lowercased)
  - `valid_until` (`now + SESSION_VALID_TIME` minutes)
- Redirects (`302 Found`) to session `return_to` path (or `/`).

#### Error responses

- `400 Bad Request`: bad/missing state, token exchange failure, session decode/get failure.
- `403 Forbidden`: profile email missing or not in allowed suffix list.
- `500 Internal Server Error`: profile parse/fetch failure, session save failure, internal parsing issues.

### `ANY {HEALTH_CHECK_PATH}` (default: `/en-US/static/html/credit.html`)

Health-check passthrough endpoint.

#### Behavior

- Proxied directly to `PROXY_URL`.
- Authentication is not enforced on this path.

### `ANY /` (catch-all protected proxy route)

All other routes go through HTTPS enforcement + auth checks before proxying.

#### Behavior

1. Enforce HTTPS:
   - If `X-Forwarded-Proto != https`, redirects (`302 Found`) to the `https://` version of the URL.
2. Validate session:
   - Session cookie must decode successfully.
   - `valid_until` must exist and be in the future.
   - `email` must exist and match one of configured `EMAIL_SUFFIX` values.
   - `OpenIDUser` must exist.
3. On success:
   - Adds header: `X-Openid-User: <OpenIDUser>`.
   - Proxies request to `PROXY_URL`.
4. On auth failure:
   - Redirects (`307 Temporary Redirect` in most cases, `302` in one legacy branch) to Google OAuth authorization URL.

## Client Integrations (Outbound Calls)

`sproxy` makes outbound calls to:

- Google OAuth token endpoint (via `golang.org/x/oauth2/google`)
- Google userinfo API: `https://www.googleapis.com/oauth2/v2/userinfo`
- Configured upstream service at `PROXY_URL` (reverse proxy target)

## Session and Cookie Notes

- Session storage uses signed/encrypted Gorilla cookie store.
- Cookie name is configurable via `COOKIE_NAME` (default: `sproxy_session`).
- Cookie max-age is configurable via `COOKIE_MAX_AGE`.
- Session validity is separately controlled by `SESSION_VALID_TIME` (minutes), enforced via `valid_until`.

## Auth Model Notes

- Identity provider is Google OAuth 2.0.
- Authorization gate is email-domain allow-list (`EMAIL_SUFFIX` values).
- Downstream identity propagation is done via `X-Openid-User`.
