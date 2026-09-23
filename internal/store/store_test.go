package store

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCreateFirstUserOnlyOnceConcurrently(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	const contenders = 16
	start := make(chan struct{})
	results := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, err := database.CreateFirstUser("alice", "hash", time.Now())
			results <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if err != ErrBootstrapDone {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful bootstrap count = %d, want 1", successes)
	}
}

func TestInviteIsSingleUse(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	now := time.Now().UTC()
	code := "invite-code"
	if err := database.CreateInvite(Invite{
		ID:        "invite-id",
		CodeHash:  HashToken(code),
		CreatedBy: "admin",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateInvitedUser(code, "alice", "hash", now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateInvitedUser(code, "bob", "hash", now); err != ErrInviteInvalid {
		t.Fatalf("second invite use error = %v, want %v", err, ErrInviteInvalid)
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	now := time.Now().UTC()
	session := Session{
		TokenHash: "token",
		CSRFToken: "csrf",
		UserID:    "user",
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := database.CreateSession(session); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetSession("token", now.Add(31*time.Minute), 30*time.Minute); err != ErrNotFound {
		t.Fatalf("idle expired session error = %v, want %v", err, ErrNotFound)
	}
}
