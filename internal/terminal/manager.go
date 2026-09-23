package terminal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

var (
	ErrTooManySessions = errors.New("too many terminal sessions")
	ErrNotRunning      = errors.New("terminal is not running")
)

type Limits struct {
	MaxPerUser int
	Shell      string
}

type Manager struct {
	mu       sync.Mutex
	sessions map[string]map[*Session]struct{}
	limits   Limits
}

type Session struct {
	id      string
	userID  string
	manager *Manager
	mu      sync.Mutex
	command *exec.Cmd
	pty     *os.File
	closed  bool
	done    chan struct{}
}

func NewManager(limits Limits) *Manager {
	if limits.MaxPerUser < 1 {
		limits.MaxPerUser = 2
	}
	return &Manager{
		sessions: make(map[string]map[*Session]struct{}),
		limits:   limits,
	}
}

func (m *Manager) Open(userID string, cols, rows uint16) (*Session, error) {
	if cols < 2 || cols > 500 || rows < 2 || rows > 300 {
		return nil, fmt.Errorf("invalid terminal dimensions")
	}

	m.mu.Lock()
	if len(m.sessions[userID]) >= m.limits.MaxPerUser {
		m.mu.Unlock()
		return nil, ErrTooManySessions
	}
	session, err := newSession(userID, m.limits.Shell, cols, rows)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	session.manager = m
	if m.sessions[userID] == nil {
		m.sessions[userID] = make(map[*Session]struct{})
	}
	m.sessions[userID][session] = struct{}{}
	m.mu.Unlock()

	go session.wait()
	return session, nil
}

func (m *Manager) remove(session *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	userSessions := m.sessions[session.userID]
	delete(userSessions, session)
	if len(userSessions) == 0 {
		delete(m.sessions, session.userID)
	}
}

func (m *Manager) CloseUser(userID string) {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions[userID]))
	for session := range m.sessions[userID] {
		sessions = append(sessions, session)
	}
	m.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
}

func (s *Session) ID() string {
	return s.id
}

func (s *Session) Wait() <-chan struct{} {
	return s.done
}

func (s *Session) Read(target []byte) (int, error) {
	s.mu.Lock()
	file := s.pty
	closed := s.closed
	s.mu.Unlock()
	if closed || file == nil {
		return 0, io.EOF
	}
	return file.Read(target)
}

func (s *Session) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.pty == nil {
		return 0, ErrNotRunning
	}
	return s.pty.Write(data)
}

func (s *Session) Resize(cols, rows uint16) error {
	if cols < 2 || cols > 500 || rows < 2 || rows > 300 {
		return fmt.Errorf("invalid terminal dimensions")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.pty == nil {
		return ErrNotRunning
	}
	return pty.Setsize(s.pty, &pty.Winsize{Cols: cols, Rows: rows})
}

func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	command := s.command
	file := s.pty
	s.mu.Unlock()

	if command != nil && command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		go func(pid int) {
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			case <-s.done:
			}
		}(command.Process.Pid)
	}
	if file != nil {
		_ = file.Close()
	}
	return nil
}

func newSession(userID, shell string, cols, rows uint16) (*Session, error) {
	if shell == "" {
		shell = "/bin/bash"
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("web-ssh terminal sessions require Linux")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	command := exec.Command(shell, "-l")
	command.Dir = home
	command.Env = terminalEnvironment(home)
	command.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
	}

	file, err := pty.StartWithSize(command, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, fmt.Errorf("start shell: %w", err)
	}
	return &Session{
		id:      fmt.Sprintf("pty-%d-%d", command.Process.Pid, time.Now().UnixNano()),
		userID:  userID,
		command: command,
		pty:     file,
		done:    make(chan struct{}),
	}, nil
}

func (s *Session) wait() {
	s.mu.Lock()
	command := s.command
	manager := s.manager
	s.mu.Unlock()
	if command != nil {
		_ = command.Wait()
	}
	close(s.done)
	if manager != nil {
		manager.remove(s)
	}
}

func terminalEnvironment(home string) []string {
	allowed := map[string]bool{
		"HOME":          true,
		"USER":          true,
		"LOGNAME":       true,
		"SHELL":         true,
		"PATH":          true,
		"LANG":          true,
		"LC_ALL":        true,
		"LC_CTYPE":      true,
		"TZ":            true,
		"COLORTERM":     true,
		"SSH_AUTH_SOCK": true,
	}
	result := []string{"HOME=" + home, "TERM=xterm-256color"}
	for _, item := range os.Environ() {
		key, _, found := strings.Cut(item, "=")
		if found && allowed[key] {
			result = append(result, item)
		}
	}
	return result
}
