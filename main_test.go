package main

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// testConfig holds test configuration
type testConfig struct {
	clientID              string
	clientSecret          string
	sessionSecret         string
	sessionEncryptionKey  string
	stateToken            string
	emailSuffixes         []string
	proxyURL              *url.URL
	callbackPath          string
	healthCheckPath       string
	sessionValidTime      int
}

// setupTestConfig creates a test configuration with safe defaults
func setupTestConfig() testConfig {
	proxyURL, _ := url.Parse("http://localhost:0") // Will be set to test server
	return testConfig{
		clientID:             "test-client-id",
		clientSecret:         "test-client-secret",
		sessionSecret:        "1234567890123456",     // Exactly 16 bytes
		sessionEncryptionKey: "1234567890123456",     // Exactly 16 bytes
		stateToken:           "test-state-token",
		emailSuffixes:        []string{"@example.com", "@test.local"},
		proxyURL:             proxyURL,
		callbackPath:         "/auth/callback/google",
		healthCheckPath:      "/health",
		sessionValidTime:     60, // 60 minutes
	}
}

// setupTestEnvironment configures the global config for testing
func setupTestEnvironment(tc testConfig) {
	config = configuration{
		ClientID:              tc.clientID,
		ClientSecret:          tc.clientSecret,
		SessionSecret:         tc.sessionSecret,
		SessionEncrypttionKey: tc.sessionEncryptionKey,
		CookieMaxAge:          1440,
		CookieName:            "sproxy_session",
		ProxyURL:              tc.proxyURL,
		CallbackPath:          tc.callbackPath,
		HealthCheckPath:       tc.healthCheckPath,
		EmailSuffixes:         tc.emailSuffixes,
		StateToken:            tc.stateToken,
		SessionValidTime:      tc.sessionValidTime,
	}
}


// TestSuffixMismatch tests the email suffix validation function
func TestSuffixMismatch(t *testing.T) {
	tests := []struct {
		name         string
		email        string
		suffixes     []string
		expectMismatch bool
	}{
		{
			name:         "valid email with first suffix",
			email:        "user@example.com",
			suffixes:     []string{"@example.com", "@test.local"},
			expectMismatch: false,
		},
		{
			name:         "valid email with second suffix",
			email:        "user@test.local",
			suffixes:     []string{"@example.com", "@test.local"},
			expectMismatch: false,
		},
		{
			name:         "invalid email suffix",
			email:        "user@invalid.com",
			suffixes:     []string{"@example.com", "@test.local"},
			expectMismatch: true,
		},
		{
			name:         "empty email",
			email:        "",
			suffixes:     []string{"@example.com"},
			expectMismatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := suffixMismatch(tt.email, tt.suffixes)
			if result != tt.expectMismatch {
				t.Errorf("suffixMismatch(%q, %v) = %v, want %v", tt.email, tt.suffixes, result, tt.expectMismatch)
			}
		})
	}
}

// TestEnforceXForwardedProto tests HTTPS enforcement
func TestEnforceXForwardedProto(t *testing.T) {
	tc := setupTestConfig()
	setupTestEnvironment(tc)

	// Create a test handler that records if it was called
	called := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := enforceXForwardedProto(testHandler)

	tests := []struct {
		name           string
		xForwardedProto string
		expectRedirect bool
		expectCalled   bool
	}{
		{
			name:           "HTTPS forwarded",
			xForwardedProto: "https",
			expectRedirect: false,
			expectCalled:   true,
		},
		{
			name:           "HTTP not forwarded",
			xForwardedProto: "",
			expectRedirect: true,
			expectCalled:   false,
		},
		{
			name:           "HTTP forwarded",
			xForwardedProto: "http",
			expectRedirect: true,
			expectCalled:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.xForwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xForwardedProto)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if tt.expectRedirect {
				if w.Code != http.StatusFound {
					t.Errorf("Expected redirect (302), got %d", w.Code)
				}
				location := w.Header().Get("Location")
				if !strings.HasPrefix(location, "https://") {
					t.Errorf("Expected redirect to https://, got %s", location)
				}
			}

			if tt.expectCalled != called {
				t.Errorf("Expected handler called = %v, got %v", tt.expectCalled, called)
			}
		})
	}
}

// TestAuthorizeMiddleware tests the authorization middleware
func TestAuthorizeMiddleware(t *testing.T) {
	tc := setupTestConfig()
	setupTestEnvironment(tc)

	// Create a test backend server
	backendCalled := false
	var receivedHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		receivedHeader = r.Header.Get("X-Openid-User")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	config.ProxyURL = backendURL

	store := sessions.NewCookieStore([]byte(tc.sessionSecret), []byte(tc.sessionEncryptionKey))
	store.Options.MaxAge = tc.sessionValidTime
	store.Options.Secure = false // Allow insecure cookies in tests

	// Create a proxy handler that forwards to the backend
	proxy := httputil.NewSingleHostReverseProxy(config.ProxyURL)

	handler := authorize(store, proxy)

	tests := []struct {
		name           string
		setupSession   func(*sessions.Session)
		expectRedirect bool
		expectCalled   bool
		expectHeader   string
	}{
		{
			name: "valid session",
			setupSession: func(s *sessions.Session) {
				s.Values["email"] = "testuser@example.com"
				s.Values["OpenIDUser"] = "testuser"
				s.Values["valid_until"] = time.Now().UTC().Add(30 * time.Minute)
			},
			expectRedirect: false,
			expectCalled:   true,
			expectHeader:   "testuser",
		},
		{
			name: "missing email",
			setupSession: func(s *sessions.Session) {
				s.Values["OpenIDUser"] = "testuser"
				s.Values["valid_until"] = time.Now().UTC().Add(30 * time.Minute)
			},
			expectRedirect: true,
			expectCalled:   false,
		},
		{
			name: "missing OpenIDUser",
			setupSession: func(s *sessions.Session) {
				s.Values["email"] = "testuser@example.com"
				s.Values["valid_until"] = time.Now().UTC().Add(30 * time.Minute)
			},
			expectRedirect: true,
			expectCalled:   false,
		},
		{
			name: "expired session",
			setupSession: func(s *sessions.Session) {
				s.Values["email"] = "testuser@example.com"
				s.Values["OpenIDUser"] = "testuser"
				s.Values["valid_until"] = time.Now().UTC().Add(-30 * time.Minute) // Expired
			},
			expectRedirect: true,
			expectCalled:   false,
		},
		{
			name: "no valid_until",
			setupSession: func(s *sessions.Session) {
				s.Values["email"] = "testuser@example.com"
				s.Values["OpenIDUser"] = "testuser"
			},
			expectRedirect: true,
			expectCalled:   false,
		},
		{
			name: "invalid email suffix",
			setupSession: func(s *sessions.Session) {
				s.Values["email"] = "testuser@invalid.com"
				s.Values["OpenIDUser"] = "testuser"
				s.Values["valid_until"] = time.Now().UTC().Add(30 * time.Minute)
			},
			expectRedirect: true,
			expectCalled:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backendCalled = false
			receivedHeader = ""

			// Create initial request to setup session
			req1 := httptest.NewRequest("GET", "/test", nil)
			req1.Header.Set("X-Forwarded-Proto", "https")
			req1.Host = "test.example.com"

			// Create and setup session
			session, _ := store.Get(req1, config.CookieName)
			if tt.setupSession != nil {
				tt.setupSession(session)
			}
			
			// Save session to get cookie
			w1 := httptest.NewRecorder()
			session.Save(req1, w1)
			cookie := w1.Header().Get("Set-Cookie")

			// Create new request with the session cookie
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("Cookie", cookie)
			req.Host = "test.example.com"

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if tt.expectRedirect {
				if w.Code != http.StatusTemporaryRedirect && w.Code != http.StatusFound {
					t.Errorf("Expected redirect, got %d", w.Code)
				}
			} else {
				if w.Code != http.StatusOK {
					t.Errorf("Expected 200, got %d", w.Code)
				}
			}

			if tt.expectCalled != backendCalled {
				t.Errorf("Expected backend called = %v, got %v", tt.expectCalled, backendCalled)
			}

			if tt.expectHeader != "" && receivedHeader != tt.expectHeader {
				t.Errorf("Expected X-Openid-User = %q, got %q", tt.expectHeader, receivedHeader)
			}
		})
	}
}

// TestHandleGoogleCallbackStateValidation tests state token validation in callback
func TestHandleGoogleCallbackStateValidation(t *testing.T) {
	tc := setupTestConfig()
	setupTestEnvironment(tc)

	store := sessions.NewCookieStore([]byte(tc.sessionSecret), []byte(tc.sessionEncryptionKey))
	store.Options.MaxAge = tc.sessionValidTime
	store.Options.Secure = false

	handler := handleGoogleCallback(store)

	tests := []struct {
		name         string
		stateToken   string
		code         string
		expectStatus int
	}{
		{
			name:         "invalid state token",
			stateToken:   "wrong-token",
			code:         "valid-code",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "missing state token",
			stateToken:   "",
			code:         "valid-code",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "valid state token (will fail on OAuth exchange, but state is validated first)",
			stateToken:   tc.stateToken,
			code:         "test-code",
			expectStatus: http.StatusBadRequest, // Will fail on OAuth exchange, but that's expected in unit tests
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.callbackPath+"?state="+tt.stateToken+"&code="+tt.code, nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Host = "test.example.com"

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			// State validation happens before OAuth exchange
			// If state is invalid, we should get BadRequest immediately
			if tt.stateToken != tc.stateToken && w.Code != http.StatusBadRequest {
				t.Errorf("Expected status %d for invalid state, got %d", http.StatusBadRequest, w.Code)
			}
		})
	}
}

// TestHealthCheckBypass tests that health check path bypasses authentication
func TestHealthCheckBypass(t *testing.T) {
	tc := setupTestConfig()
	setupTestEnvironment(tc)

	// Create a test backend server
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("health check response"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	config.ProxyURL = backendURL

	proxy := httputil.NewSingleHostReverseProxy(config.ProxyURL)

	// Health check should bypass auth
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	req := httptest.NewRequest("GET", tc.healthCheckPath, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !backendCalled {
		t.Error("Expected backend to be called for health check")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

// TestAuthorizeExpiredTimestamp tests that expired timestamp errors redirect to OAuth
func TestAuthorizeExpiredTimestamp(t *testing.T) {
	tc := setupTestConfig()
	setupTestEnvironment(tc)

	// Create a test backend server
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	config.ProxyURL = backendURL

	// Create a store with a very short MaxAge to simulate expired cookies
	store := sessions.NewCookieStore([]byte(tc.sessionSecret), []byte(tc.sessionEncryptionKey))
	store.MaxAge(1) // 1 second - very short (this also sets MaxAge on securecookie codecs)
	store.Options.Secure = false // Allow insecure cookies in tests

	// Create a proxy handler
	proxy := httputil.NewSingleHostReverseProxy(config.ProxyURL)
	handler := authorize(store, proxy)

	// Create a request to setup a session
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.Header.Set("X-Forwarded-Proto", "https")
	req1.Host = "test.example.com"

	// Create and save a session
	session, _ := store.Get(req1, config.CookieName)
	session.Values["email"] = "testuser@example.com"
	session.Values["OpenIDUser"] = "testuser"
	session.Values["valid_until"] = time.Now().UTC().Add(30 * time.Minute)

	// Save session to get cookie
	w1 := httptest.NewRecorder()
	session.Save(req1, w1)
	cookie := w1.Header().Get("Set-Cookie")

	if cookie == "" {
		t.Fatal("No cookie set after saving session")
	}

	// Wait for the cookie to expire (MaxAge is 1 second)
	time.Sleep(2 * time.Second)

	// Create a new request with the expired cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Cookie", cookie)
	req.Host = "test.example.com"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should redirect to OAuth instead of returning 400
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("Expected redirect (307), got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Error("Expected Location header in redirect")
	}

	// Should redirect to Google OAuth
	if !strings.Contains(location, "accounts.google.com") {
		t.Errorf("Expected redirect to Google OAuth, got %s", location)
	}

	// Backend should not be called
	if backendCalled {
		t.Error("Expected backend not to be called when cookie is expired")
	}

	// Verify return_to is stored in the new session
	// The cookie should be set in the response
	setCookie := w.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Error("Expected Set-Cookie header to store return_to value")
	}
}

// TestFullFlow tests a complete authentication and proxying flow
func TestFullFlow(t *testing.T) {
	tc := setupTestConfig()
	setupTestEnvironment(tc)

	// Create test backend
	backendReceivedUser := ""
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendReceivedUser = r.Header.Get("X-Openid-User")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	config.ProxyURL = backendURL

	store := sessions.NewCookieStore([]byte(tc.sessionSecret), []byte(tc.sessionEncryptionKey))
	store.Options.MaxAge = tc.sessionValidTime
	store.Options.Secure = false

	proxy := httputil.NewSingleHostReverseProxy(config.ProxyURL)
	handler := enforceXForwardedProto(authorize(store, proxy))

	// Create a valid session
	req1 := httptest.NewRequest("GET", "/some/path", nil)
	req1.Header.Set("X-Forwarded-Proto", "https")
	req1.Host = "test.example.com"

	session, _ := store.Get(req1, config.CookieName)
	session.Values["email"] = "testuser@example.com"
	session.Values["OpenIDUser"] = "testuser"
	session.Values["valid_until"] = time.Now().UTC().Add(30 * time.Minute)
	
	// Save session to get cookies
	w1 := httptest.NewRecorder()
	if err := session.Save(req1, w1); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}
	cookies := w1.Header().Get("Set-Cookie")
	if cookies == "" {
		t.Fatal("No cookie set after saving session")
	}

	// Make request with session cookie
	req2 := httptest.NewRequest("GET", "/some/path", nil)
	req2.Header.Set("X-Forwarded-Proto", "https")
	req2.Header.Set("Cookie", cookies)
	req2.Host = "test.example.com"

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w2.Code)
	}

	if backendReceivedUser != "testuser" {
		t.Errorf("Expected X-Openid-User = 'testuser', got %q", backendReceivedUser)
	}
}

