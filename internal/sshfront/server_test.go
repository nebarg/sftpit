package sshfront_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
	"github.com/nebarg/sftpit/internal/testutil"
)

func TestNewRejectsInvalidConfig(t *testing.T) {
	handler := func(context.Context, *sshfront.Conn, io.ReadWriteCloser) error { return nil }
	validUser := sshfront.User{Name: "test", Password: testPassword}

	tests := []struct {
		name    string
		cfg     sshfront.Config
		wantErr string
	}{
		{
			name:    "no host keys",
			cfg:     sshfront.Config{Users: []sshfront.User{validUser}, Handler: handler},
			wantErr: "host key",
		},
		{
			name:    "no handler",
			cfg:     sshfront.Config{HostKeys: hostKeys, Users: []sshfront.User{validUser}},
			wantErr: "handler",
		},
		{
			name:    "no users",
			cfg:     sshfront.Config{HostKeys: hostKeys, Handler: handler},
			wantErr: "at least one user",
		},
		{
			name: "unnamed user",
			cfg: sshfront.Config{HostKeys: hostKeys, Handler: handler, Users: []sshfront.User{
				{Password: testPassword},
			}},
			wantErr: "needs a name",
		},
		{
			name: "duplicate user",
			cfg: sshfront.Config{HostKeys: hostKeys, Handler: handler, Users: []sshfront.User{
				validUser, validUser,
			}},
			wantErr: `duplicate user "test"`,
		},
		{
			name: "user without credentials",
			cfg: sshfront.Config{HostKeys: hostKeys, Handler: handler, Users: []sshfront.User{
				{Name: "test"},
			}},
			wantErr: "needs a password or an authorized key",
		},
		{
			name: "relative home",
			cfg: sshfront.Config{HostKeys: hostKeys, Handler: handler, Users: []sshfront.User{
				{Name: "test", Password: testPassword, Home: "incoming"},
			}},
			wantErr: "not an absolute path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sshfront.New(tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordLogin(t *testing.T) {
	handler, conns, _ := connPublisher()
	addr, _ := startServer(t, sshfront.Config{
		Handler: handler,
	})

	tests := []struct {
		name     string
		user     string
		password string
		wantOK   bool
	}{
		{name: "correct password", user: "test", password: testPassword, wantOK: true},
		{name: "wrong password", user: "test", password: "nope"},
		{name: "unknown user", user: "nobody", password: testPassword},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := dial(addr, tt.user, ssh.Password(tt.password))
			if !tt.wantOK {
				if err == nil {
					client.Close()
					t.Fatal("login succeeded, want failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("login failed: %v", err)
			}
			defer client.Close()

			conn := openSFTP(t, client, conns)
			if conn.User() != "test" || conn.Home() != "/" || conn.KeyFingerprint() != "" {
				t.Errorf("conn = user %q home %q fingerprint %q, want test, /, empty",
					conn.User(), conn.Home(), conn.KeyFingerprint())
			}
		})
	}
}

func TestKeyboardInteractiveLogin(t *testing.T) {
	handler, conns, _ := connPublisher()
	addr, _ := startServer(t, sshfront.Config{
		Handler: handler,
	})
	answer := func(password string) ssh.AuthMethod {
		return ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = password
			}
			return answers, nil
		})
	}

	client, err := dial(addr, "test", answer(testPassword))
	if err != nil {
		t.Fatalf("login with correct password failed: %v", err)
	}
	defer client.Close()
	if conn := openSFTP(t, client, conns); conn.User() != "test" {
		t.Errorf("conn.User() = %q, want test", conn.User())
	}

	if client, err := dial(addr, "test", answer("nope")); err == nil {
		client.Close()
		t.Error("login with wrong password succeeded")
	}
}

func TestPublicKeyLogin(t *testing.T) {
	partnerKey := newClientKey(t)
	otherKey := newClientKey(t)
	handler, conns, _ := connPublisher()
	addr, _ := startServer(t, sshfront.Config{
		Users: []sshfront.User{
			{Name: "test", Password: testPassword, AuthorizedKeys: []ssh.PublicKey{otherKey.PublicKey()}},
			{Name: "partner-b", AuthorizedKeys: []ssh.PublicKey{partnerKey.PublicKey()}, Home: "/partner-b/"},
		},
		Handler: handler,
	})

	before := time.Now()
	client, err := dial(addr, "partner-b", ssh.PublicKeys(partnerKey))
	if err != nil {
		t.Fatalf("login with authorized key failed: %v", err)
	}
	defer client.Close()
	conn := openSFTP(t, client, conns)
	// The server serves a channel only once the connection has
	// authenticated.
	after := time.Now()
	if at := conn.Authenticated(); at.Before(before) || at.After(after) {
		t.Errorf("conn.Authenticated() = %v, want during the login, between %v and %v", at, before, after)
	}
	wantFingerprint := ssh.FingerprintSHA256(partnerKey.PublicKey())
	if conn.User() != "partner-b" || conn.Home() != "/partner-b" || conn.KeyFingerprint() != wantFingerprint {
		t.Errorf("conn = user %q home %q fingerprint %q, want partner-b, /partner-b, %s",
			conn.User(), conn.Home(), conn.KeyFingerprint(), wantFingerprint)
	}

	if client, err := dial(addr, "partner-b", ssh.PublicKeys(newClientKey(t))); err == nil {
		client.Close()
		t.Error("login with unknown key succeeded")
	}
	if client, err := dial(addr, "partner-b", ssh.PublicKeys(otherKey)); err == nil {
		client.Close()
		t.Error("login with another user's key succeeded")
	}
}

func TestHostKeyAlgorithms(t *testing.T) {
	addr, _ := startServer(t, sshfront.Config{})

	tests := []struct {
		algorithm string
		wantOK    bool
	}{
		{algorithm: ssh.KeyAlgoED25519, wantOK: true},
		{algorithm: ssh.KeyAlgoRSASHA512, wantOK: true},
		{algorithm: ssh.KeyAlgoRSASHA256, wantOK: true},
		{algorithm: ssh.KeyAlgoRSA},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
				User:              "test",
				Auth:              []ssh.AuthMethod{ssh.Password(testPassword)},
				HostKeyCallback:   trustHostKeys,
				HostKeyAlgorithms: []string{tt.algorithm},
				Timeout:           waitTimeout,
			})
			if err == nil {
				client.Close()
			}
			if gotOK := err == nil; gotOK != tt.wantOK {
				t.Fatalf("handshake with only %s: error = %v, want success %v", tt.algorithm, err, tt.wantOK)
			}
		})
	}
}

func TestOnlySFTPSubsystemIsServed(t *testing.T) {
	handler, conns, _ := connPublisher()
	addr, _ := startServer(t, sshfront.Config{
		Handler: handler,
	})
	client := mustDial(t, addr, "test", ssh.Password(testPassword))

	refused := []struct {
		name    string
		request func(*ssh.Session) error
	}{
		{name: "exec", request: func(s *ssh.Session) error { return s.Run("ls") }},
		{name: "shell", request: func(s *ssh.Session) error { return s.Shell() }},
		{name: "pty", request: func(s *ssh.Session) error { return s.RequestPty("xterm", 40, 80, ssh.TerminalModes{}) }},
		{name: "other subsystem", request: func(s *ssh.Session) error { return s.RequestSubsystem("netconf") }},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer session.Close()
			if err := tt.request(session); err == nil {
				t.Fatalf("%s request accepted, want refusal", tt.name)
			}
		})
	}

	t.Run("second subsystem on one channel", func(t *testing.T) {
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer session.Close()
		if err := session.RequestSubsystem("sftp"); err != nil {
			t.Fatalf("first sftp subsystem request: %v", err)
		}
		testutil.Receive(t, conns)
		if err := session.RequestSubsystem("sftp"); err == nil {
			t.Fatal("second sftp subsystem request accepted, want refusal")
		}
	})

	t.Run("port forwarding", func(t *testing.T) {
		if fwd, err := client.Dial("tcp", "127.0.0.1:1"); err == nil {
			fwd.Close()
			t.Fatal("direct-tcpip channel accepted, want refusal")
		}
	})
}

func TestSFTPTransferThroughFrontEnd(t *testing.T) {
	addr, _ := startServer(t, sshfront.Config{})
	client := mustDial(t, addr, "test", ssh.Password(testPassword))
	sftpClient, err := sftp.NewClient(client, sftp.UseConcurrentWrites(true))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer sftpClient.Close()

	want := make([]byte, 4<<20)
	rand.Read(want)

	f, err := sftpClient.Create("/orders.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.ReadFrom(bytes.NewReader(want)); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close after write: %v", err)
	}

	f, err = sftpClient.Open("/orders.bin")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	var got bytes.Buffer
	if _, err := f.WriteTo(&got); err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("downloaded %d bytes that differ from the %d uploaded", got.Len(), len(want))
	}
}

func TestHandlerResultSetsExitStatus(t *testing.T) {
	tests := []struct {
		name       string
		handlerErr error
		wantStatus int
	}{
		{name: "success", wantStatus: 0},
		{name: "failure", handlerErr: errors.New("backend unavailable"), wantStatus: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, _ := startServer(t, sshfront.Config{
				Handler: func(context.Context, *sshfront.Conn, io.ReadWriteCloser) error {
					return tt.handlerErr
				},
			})
			client := mustDial(t, addr, "test", ssh.Password(testPassword))
			if got := sftpExitStatus(t, client); got != tt.wantStatus {
				t.Errorf("exit status = %d, want %d", got, tt.wantStatus)
			}
		})
	}
}

func TestHandlerFailuresAreLogged(t *testing.T) {
	var logs testutil.SyncBuffer
	stopped := make(chan struct{})
	addr, srv := startServer(t, sshfront.Config{
		Users: []sshfront.User{{Name: "fails", Password: testPassword}, {Name: "waits", Password: testPassword}},
		Handler: func(ctx context.Context, conn *sshfront.Conn, _ io.ReadWriteCloser) error {
			if conn.User() == "fails" {
				return errors.New("backend unavailable")
			}
			defer close(stopped)
			<-ctx.Done()
			return ctx.Err()
		},
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})

	sftpExitStatus(t, mustDial(t, addr, "fails", ssh.Password(testPassword)))
	client := mustDial(t, addr, "waits", ssh.Password(testPassword))
	channel, _, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	if ok, err := channel.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"})); err != nil || !ok {
		t.Fatalf("subsystem request: ok %v, err %v", ok, err)
	}
	client.Close()
	select {
	case <-stopped:
	case <-time.After(waitTimeout):
		t.Fatal("handler was not cancelled when its connection closed")
	}
	// Close waits for every handler's result to be logged.
	srv.Close()

	logged := logs.String()
	if !strings.Contains(logged, `msg="sftp handler failed" conn=1 user=fails err="backend unavailable"`) {
		t.Errorf("the failing handler was not logged:\n%s", logged)
	}
	if strings.Contains(logged, "user=waits") {
		t.Errorf("a handler stopped by its connection closing was logged as a failure:\n%s", logged)
	}
}

func TestHandlerPanicIsContained(t *testing.T) {
	var logs testutil.SyncBuffer
	addr, _ := startServer(t, sshfront.Config{
		Handler: func(context.Context, *sshfront.Conn, io.ReadWriteCloser) error {
			panic("proxy bug")
		},
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})

	for range 2 {
		client := mustDial(t, addr, "test", ssh.Password(testPassword))
		if got := sftpExitStatus(t, client); got != 1 {
			t.Errorf("exit status after a handler panic = %d, want 1", got)
		}
	}

	logged := logs.String()
	for _, want := range []string{"sftp handler panicked", "proxy bug", "stack="} {
		if !strings.Contains(logged, want) {
			t.Errorf("log does not contain %q:\n%s", want, logged)
		}
	}
}

func TestServeRetriesFailedAccepts(t *testing.T) {
	ln := newFlakyListener(t, 3)
	serve(t, ln, sshfront.Config{})

	client := mustDial(t, ln.Addr().String(), "test", ssh.Password(testPassword))
	if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
		t.Fatalf("connection after accept failures: %v", err)
	}
}

func TestCloseInterruptsAcceptRetry(t *testing.T) {
	ln := newFlakyListener(t, math.MaxInt32)
	srv := newServer(t, sshfront.Config{})
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	for range 3 {
		testutil.Receive(t, ln.attempts)
	}

	start := time.Now()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := testutil.Receive(t, served); !errors.Is(err, sshfront.ErrServerClosed) {
		t.Errorf("Serve returned %v, want ErrServerClosed", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Serve took %v to stop during an accept retry", elapsed)
	}
}

func TestServeReturnsWhenListenerClosedElsewhere(t *testing.T) {
	srv := newServer(t, sshfront.Config{})
	t.Cleanup(func() { srv.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	ln.Close()

	err = testutil.Receive(t, served)
	if !errors.Is(err, net.ErrClosed) || errors.Is(err, sshfront.ErrServerClosed) {
		t.Errorf("Serve returned %v, want the listener's close error", err)
	}
}

func TestServerCloseInterruptsHandshake(t *testing.T) {
	addr, srv := startServer(t, sshfront.Config{
		HandshakeTimeout: time.Minute,
	})
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()

	closed := make(chan error, 1)
	go func() { closed <- srv.Close() }()
	if err := testutil.Receive(t, closed); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	addr, _ := startServer(t, sshfront.Config{
		HandshakeTimeout: 200 * time.Millisecond,
	})
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if _, err := io.ReadAll(raw); err != nil {
		t.Fatalf("server did not close an idle handshake: %v", err)
	}
}

type flakyListener struct {
	net.Listener
	failuresLeft atomic.Int64
	attempts     chan struct{}
}

func newFlakyListener(t *testing.T, failures int64) *flakyListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	flaky := &flakyListener{Listener: ln, attempts: make(chan struct{}, 16)}
	flaky.failuresLeft.Store(failures)
	return flaky
}

func (l *flakyListener) Accept() (net.Conn, error) {
	select {
	case l.attempts <- struct{}{}:
	default:
	}
	if l.failuresLeft.Add(-1) >= 0 {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	}
	return l.Listener.Accept()
}

func sftpExitStatus(t *testing.T, client *ssh.Client) int {
	t.Helper()
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	defer channel.Close()
	ok, err := channel.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
	if err != nil || !ok {
		t.Fatalf("subsystem request: ok %v, err %v", ok, err)
	}

	for req := range requests {
		if req.Type != "exit-status" {
			continue
		}
		var msg struct{ Status uint32 }
		if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
			t.Fatalf("exit-status payload: %v", err)
		}
		return int(msg.Status)
	}
	t.Fatal("channel closed without an exit status")
	return 0
}
