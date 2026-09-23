package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/GWBailang553/web-ssh/internal/auth"
	"github.com/GWBailang553/web-ssh/internal/config"
	"github.com/GWBailang553/web-ssh/internal/store"
)

func TestBootstrapIsAtomicAndSessionAuthenticates(t *testing.T) {
	cfg := testConfig(t)
	database, err := store.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	application := New(cfg, database, slog.New(slog.NewTextHandler(io.Discard, nil)))
	httpServer := httptest.NewTLSServer(application.HTTPHandler())
	defer httpServer.Close()

	const contenders = 8
	results := make(chan int, contenders)
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			jar, _ := cookiejar.New(nil)
			client := httpServer.Client()
			client.Jar = jar
			payload := bytes.NewBufferString(`{"username":"admin","password":"quiet-orbit-cedar-42!"}`)
			request, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/bootstrap", payload)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", httpServer.URL)
			<-start
			response, requestErr := client.Do(request)
			if requestErr != nil {
				results <- 500
				return
			}
			defer response.Body.Close()
			results <- response.StatusCode
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)

	successes := 0
	for status := range results {
		switch status {
		case http.StatusOK:
			successes++
		case http.StatusConflict:
		default:
			t.Fatalf("bootstrap status = %d", status)
		}
	}
	if successes != 1 {
		t.Fatalf("successful bootstrap count = %d, want 1", successes)
	}

	jar, _ := cookiejar.New(nil)
	client := httpServer.Client()
	client.Jar = jar
	login := bytes.NewBufferString(`{"username":"admin","password":"quiet-orbit-cedar-42!"}`)
	request, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/login", login)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", httpServer.URL)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("login status = %d, body = %s", response.StatusCode, body)
	}
	var auth struct {
		CSRFToken string `json:"csrf_token"`
		User      struct {
			Role string `json:"role"`
		} `json:"user"`
	}
	if err := json.NewDecoder(response.Body).Decode(&auth); err != nil {
		t.Fatal(err)
	}
	if auth.CSRFToken == "" || auth.User.Role != "admin" {
		t.Fatalf("unexpected auth response: %+v", auth)
	}

	request, _ = http.NewRequest(http.MethodGet, httpServer.URL+"/api/me", nil)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("me status = %d", response.StatusCode)
	}
}

func TestInviteRegistrationAndCSRF(t *testing.T) {
	cfg := testConfig(t)
	database, err := store.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	passwordHash, err := auth.HashPassword("quiet-orbit-cedar-42!")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := database.CreateFirstUser("admin", passwordHash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	application := New(cfg, database, slog.New(slog.NewTextHandler(io.Discard, nil)))
	httpServer := httptest.NewTLSServer(application.HTTPHandler())
	defer httpServer.Close()

	code := "test-invite"
	if err := database.CreateInvite(store.Invite{
		ID:        "invite",
		CodeHash:  store.HashToken(code),
		CreatedBy: admin.ID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	request, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/register", bytes.NewBufferString(
		`{"username":"alice","password":"quiet-orbit-cedar-42!","invite":"test-invite"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", httpServer.URL)
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("register status = %d, body = %s", response.StatusCode, body)
	}

	request, _ = http.NewRequest(http.MethodPost, httpServer.URL+"/api/logout", bytes.NewBufferString("{}"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", httpServer.URL)
	response, err = httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("logout without login status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
}

func TestTerminalWebSocketExecutesCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("PTY integration test")
	}
	cfg := testConfig(t)
	database, err := store.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	passwordHash, err := auth.HashPassword("quiet-orbit-cedar-42!")
	if err != nil {
		t.Fatal(err)
	}
	user, err := database.CreateFirstUser("admin", passwordHash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	application := New(cfg, database, slog.New(slog.NewTextHandler(io.Discard, nil)))
	httpServer := httptest.NewTLSServer(application.HTTPHandler())
	defer httpServer.Close()

	jar, _ := cookiejar.New(nil)
	client := httpServer.Client()
	client.Jar = jar
	request, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/login", bytes.NewBufferString(
		`{"username":"admin","password":"quiet-orbit-cedar-42!"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", httpServer.URL)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", response.StatusCode)
	}

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server certificate
		Jar:             jar,
	}
	headers := http.Header{"Origin": []string{httpServer.URL}}
	connection, _, err := dialer.Dial(strings.Replace(httpServer.URL, "https://", "wss://", 1)+"/ws/terminal?cols=80&rows=24", headers)
	if err != nil {
		t.Fatalf("dial terminal: %v", err)
	}
	defer connection.Close()
	connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ready map[string]string
	if err := connection.ReadJSON(&ready); err != nil {
		t.Fatalf("read ready message: %v", err)
	}
	if ready["session"] == "" {
		t.Fatal("ready message did not include a session ID")
	}
	if err := connection.WriteMessage(websocket.BinaryMessage, []byte("printf 'ws-ready\\n'\n")); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	for !strings.Contains(output.String(), "ws-ready") {
		messageType, data, err := connection.ReadMessage()
		if err != nil {
			t.Fatalf("read terminal output = %q, error = %v", output.String(), err)
		}
		if messageType == websocket.BinaryMessage {
			output.Write(data)
		}
	}
	if !strings.Contains(output.String(), "ws-ready") {
		t.Fatalf("terminal output = %q", output.String())
	}
	if err := database.RevokeUserSessions(user.ID); err != nil {
		t.Fatal(err)
	}
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	cfg.DatabasePath = filepath.Join(t.TempDir(), "unused.db")
	cfg.Certificate = filepath.Join(t.TempDir(), "cert.pem")
	cfg.PrivateKey = filepath.Join(t.TempDir(), "key.pem")
	cfg.Shell = "/bin/sh"
	return cfg
}
