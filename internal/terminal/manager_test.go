package terminal

import (
	"bytes"
	"testing"
	"time"
)

func TestManagerLimitsAndCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("PTY integration test")
	}
	manager := NewManager(Limits{MaxPerUser: 1, Shell: "/bin/sh"})
	session, err := manager.Open("user-1", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Open("user-1", 80, 24); err != ErrTooManySessions {
		t.Fatalf("second Open() error = %v, want %v", err, ErrTooManySessions)
	}
	if _, err := session.Write([]byte("printf 'ready\\n'\n")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	var output bytes.Buffer
	for time.Now().Before(deadline) && !bytes.Contains(output.Bytes(), []byte("ready")) {
		_ = session.pty.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		count, readErr := session.Read(buffer)
		if count > 0 {
			output.Write(buffer[:count])
		}
		if readErr != nil && time.Now().After(deadline) {
			break
		}
	}
	if !bytes.Contains(output.Bytes(), []byte("ready")) {
		t.Fatalf("terminal output = %q, want readiness marker", output.String())
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.Wait():
	case <-time.After(3 * time.Second):
		t.Fatal("terminal did not exit after Close()")
	}
}
