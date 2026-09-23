package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrBootstrapDone = errors.New("bootstrap already completed")
	ErrInviteInvalid = errors.New("invite is invalid, expired, or already used")
	ErrResetInvalid  = errors.New("reset code is invalid, expired, or already used")
)

var (
	bucketMeta       = []byte("meta")
	bucketUsers      = []byte("users")
	bucketUsersNames = []byte("users_by_name")
	bucketSessions   = []byte("sessions")
	bucketInvites    = []byte("invites")
	bucketResets     = []byte("password_resets")
	bucketAudit      = []byte("audit")
)

type User struct {
	ID             string    `json:"id"`
	Username       string    `json:"username"`
	PasswordHash   string    `json:"password_hash"`
	Role           string    `json:"role"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	FailedAttempts int       `json:"failed_attempts"`
	LockedUntil    time.Time `json:"locked_until,omitempty"`
}

type Session struct {
	TokenHash string    `json:"token_hash"`
	CSRFToken string    `json:"csrf_token"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
}

type Invite struct {
	ID        string    `json:"id"`
	CodeHash  string    `json:"code_hash"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
	UsedBy    string    `json:"used_by,omitempty"`
}

type PasswordReset struct {
	CodeHash  string    `json:"code_hash"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

type AuditEvent struct {
	ID        uint64    `json:"id"`
	Time      time.Time `json:"time"`
	Event     string    `json:"event"`
	ActorID   string    `json:"actor_id,omitempty"`
	Username  string    `json:"username,omitempty"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Details   string    `json:"details,omitempty"`
}

type Store struct {
	db *bolt.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	result := &Store{db: db}
	if err := result.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return result, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) initialize() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{
			bucketMeta,
			bucketUsers,
			bucketUsersNames,
			bucketSessions,
			bucketInvites,
			bucketResets,
			bucketAudit,
		} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) HasUsers() (bool, error) {
	var hasUsers bool
	err := s.db.View(func(tx *bolt.Tx) error {
		hasUsers = tx.Bucket(bucketUsers).Stats().KeyN > 0
		return nil
	})
	return hasUsers, err
}

func (s *Store) CreateFirstUser(username, passwordHash string, now time.Time) (User, error) {
	user := User{
		ID:           newID(),
		Username:     username,
		PasswordHash: passwordHash,
		Role:         "admin",
		Enabled:      true,
		CreatedAt:    now.UTC(),
		UpdatedAt:    now.UTC(),
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bucketUsers)
		if users.Stats().KeyN != 0 {
			return ErrBootstrapDone
		}
		names := tx.Bucket(bucketUsersNames)
		nameKey := normalizeUsername(username)
		if names.Get(nameKey) != nil {
			return ErrAlreadyExists
		}
		return putJSON(users, user.ID, user, func() error {
			return names.Put(nameKey, []byte(user.ID))
		})
	})
	return user, err
}

func (s *Store) CreateInvitedUser(inviteCode, username, passwordHash string, now time.Time) (User, error) {
	user := User{
		ID:           newID(),
		Username:     username,
		PasswordHash: passwordHash,
		Role:         "user",
		Enabled:      true,
		CreatedAt:    now.UTC(),
		UpdatedAt:    now.UTC(),
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		invites := tx.Bucket(bucketInvites)
		hash := hashToken(inviteCode)
		raw := invites.Get([]byte(hash))
		if raw == nil {
			return ErrInviteInvalid
		}
		var invite Invite
		if err := json.Unmarshal(raw, &invite); err != nil {
			return err
		}
		if !invite.UsedAt.IsZero() || !now.UTC().Before(invite.ExpiresAt) {
			return ErrInviteInvalid
		}

		names := tx.Bucket(bucketUsersNames)
		nameKey := normalizeUsername(username)
		if names.Get(nameKey) != nil {
			return ErrAlreadyExists
		}
		users := tx.Bucket(bucketUsers)
		if err := putJSON(users, user.ID, user, nil); err != nil {
			return err
		}
		if err := names.Put(nameKey, []byte(user.ID)); err != nil {
			return err
		}

		invite.UsedAt = now.UTC()
		invite.UsedBy = user.ID
		updated, err := json.Marshal(invite)
		if err != nil {
			return err
		}
		return invites.Put([]byte(hash), updated)
	})
	return user, err
}

func (s *Store) GetUserByID(id string) (User, error) {
	var user User
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketUsers), []byte(id), &user)
	})
	return user, err
}

func (s *Store) GetUserByUsername(username string) (User, error) {
	var user User
	err := s.db.View(func(tx *bolt.Tx) error {
		id := tx.Bucket(bucketUsersNames).Get(normalizeUsername(username))
		if id == nil {
			return ErrNotFound
		}
		return getJSON(tx.Bucket(bucketUsers), id, &user)
	})
	return user, err
}

func (s *Store) ListUsers() ([]User, error) {
	var users []User
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUsers).ForEach(func(_, value []byte) error {
			var user User
			if err := json.Unmarshal(value, &user); err != nil {
				return err
			}
			users = append(users, user)
			return nil
		})
	})
	return users, err
}

func (s *Store) RecordLoginFailure(userID string, now time.Time, maxAttempts int, lockFor time.Duration) (User, error) {
	var result User
	err := s.db.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bucketUsers)
		if err := getJSON(users, []byte(userID), &result); err != nil {
			return err
		}
		result.FailedAttempts++
		if result.FailedAttempts >= maxAttempts {
			result.LockedUntil = now.Add(lockFor).UTC()
		}
		result.UpdatedAt = now.UTC()
		return putJSON(users, result.ID, result, nil)
	})
	return result, err
}

func (s *Store) ClearLoginFailures(userID string, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bucketUsers)
		var user User
		if err := getJSON(users, []byte(userID), &user); err != nil {
			return err
		}
		user.FailedAttempts = 0
		user.LockedUntil = time.Time{}
		user.UpdatedAt = now.UTC()
		return putJSON(users, user.ID, user, nil)
	})
}

func (s *Store) UpdateUser(user User) error {
	user.UpdatedAt = time.Now().UTC()
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketUsers), user.ID, user, nil)
	})
}

func (s *Store) CreateSession(session Session) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketSessions), session.TokenHash, session, nil)
	})
}

func (s *Store) GetSession(tokenHash string, now time.Time, idleTimeout time.Duration) (Session, error) {
	var session Session
	err := s.db.Update(func(tx *bolt.Tx) error {
		sessions := tx.Bucket(bucketSessions)
		if err := getJSON(sessions, []byte(tokenHash), &session); err != nil {
			return err
		}
		if !now.UTC().Before(session.ExpiresAt) || now.UTC().Sub(session.LastSeen) > idleTimeout {
			_ = sessions.Delete([]byte(tokenHash))
			return ErrNotFound
		}
		session.LastSeen = now.UTC()
		return putJSON(sessions, session.TokenHash, session, nil)
	})
	return session, err
}

func (s *Store) RevokeSession(tokenHash string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSessions).Delete([]byte(tokenHash))
	})
}

func (s *Store) RevokeUserSessions(userID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		sessions := tx.Bucket(bucketSessions)
		var keys [][]byte
		if err := sessions.ForEach(func(key, value []byte) error {
			var session Session
			if err := json.Unmarshal(value, &session); err != nil {
				return err
			}
			if session.UserID == userID {
				keys = append(keys, bytes.Clone(key))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range keys {
			if err := sessions.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) CreateInvite(invite Invite) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketInvites), invite.CodeHash, invite, nil)
	})
}

func (s *Store) ListInvites(now time.Time) ([]Invite, error) {
	var invites []Invite
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketInvites)
		if err := bucket.ForEach(func(_, value []byte) error {
			var invite Invite
			if err := json.Unmarshal(value, &invite); err != nil {
				return err
			}
			if invite.UsedAt.IsZero() && now.UTC().After(invite.ExpiresAt) {
				return nil
			}
			invites = append(invites, invite)
			return nil
		}); err != nil {
			return err
		}
		return nil
	})
	return invites, err
}

func (s *Store) DeleteInvite(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketInvites)
		var key []byte
		if err := bucket.ForEach(func(candidate, value []byte) error {
			var invite Invite
			if err := json.Unmarshal(value, &invite); err != nil {
				return err
			}
			if invite.ID == id {
				key = bytes.Clone(candidate)
			}
			return nil
		}); err != nil {
			return err
		}
		if key == nil {
			return ErrNotFound
		}
		return bucket.Delete(key)
	})
}

func (s *Store) CreatePasswordReset(reset PasswordReset) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketResets), reset.CodeHash, reset, nil)
	})
}

func (s *Store) ConsumePasswordReset(code, passwordHash string, now time.Time) (User, error) {
	var user User
	err := s.db.Update(func(tx *bolt.Tx) error {
		resets := tx.Bucket(bucketResets)
		hash := hashToken(code)
		raw := resets.Get([]byte(hash))
		if raw == nil {
			return ErrResetInvalid
		}
		var reset PasswordReset
		if err := json.Unmarshal(raw, &reset); err != nil {
			return err
		}
		if !reset.UsedAt.IsZero() || !now.UTC().Before(reset.ExpiresAt) {
			return ErrResetInvalid
		}
		users := tx.Bucket(bucketUsers)
		if err := getJSON(users, []byte(reset.UserID), &user); err != nil {
			return ErrResetInvalid
		}
		user.PasswordHash = passwordHash
		user.FailedAttempts = 0
		user.LockedUntil = time.Time{}
		user.UpdatedAt = now.UTC()
		if err := putJSON(users, user.ID, user, nil); err != nil {
			return err
		}
		reset.UsedAt = now.UTC()
		updated, err := json.Marshal(reset)
		if err != nil {
			return err
		}
		return resets.Put([]byte(hash), updated)
	})
	return user, err
}

func (s *Store) AppendAudit(event AuditEvent) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketAudit)
		sequence, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		event.ID = sequence
		if event.Time.IsZero() {
			event.Time = time.Now().UTC()
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			return err
		}
		return bucket.Put(uint64Key(sequence), encoded)
	})
}

func (s *Store) ListAudit(limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var result []AuditEvent
	err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(bucketAudit).Cursor()
		for key, value := cursor.Last(); key != nil && len(result) < limit; key, value = cursor.Prev() {
			var event AuditEvent
			if err := json.Unmarshal(value, &event); err != nil {
				return err
			}
			result = append(result, event)
		}
		return nil
	})
	return result, err
}

func (s *Store) PruneAudit(cutoff time.Time, maxEvents int) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketAudit)
		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			var event AuditEvent
			if err := json.Unmarshal(value, &event); err != nil {
				return err
			}
			if !event.Time.Before(cutoff) {
				break
			}
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
		count := bucket.Stats().KeyN
		if count <= maxEvents {
			return nil
		}
		excess := count - maxEvents
		cursor = bucket.Cursor()
		for key, _ := cursor.First(); key != nil && excess > 0; key, _ = cursor.Next() {
			if err := cursor.Delete(); err != nil {
				return err
			}
			excess--
		}
		return nil
	})
}

func HashToken(token string) string {
	return hashToken(token)
}

func NewToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func NewID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func newID() string {
	id, err := NewID()
	if err != nil {
		panic(err)
	}
	return id
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func normalizeUsername(username string) []byte {
	return []byte(strings.ToLower(strings.TrimSpace(username)))
}

func putJSON(bucket *bolt.Bucket, key string, value any, afterPut func() error) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := bucket.Put([]byte(key), encoded); err != nil {
		return err
	}
	if afterPut != nil {
		return afterPut()
	}
	return nil
}

func getJSON(bucket *bolt.Bucket, key []byte, target any) error {
	value := bucket.Get(key)
	if value == nil {
		return ErrNotFound
	}
	return json.Unmarshal(value, target)
}

func uint64Key(value uint64) []byte {
	var key [8]byte
	for index := 7; index >= 0; index-- {
		key[index] = byte(value)
		value >>= 8
	}
	return key[:]
}
