package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

const (
	// heldOffset is where a transfer's reply is held back. OpenSSH waits for
	// the reply to its first WRITE and starts with one READ in flight, so
	// the hold comes once every client has several requests outstanding.
	heldOffset = 1 << 20

	// replyHold is how long the reply is held back.
	replyHold = 300 * time.Millisecond
)

// TestClientsTolerateOutOfOrderReplies holds back the reply to one WRITE of
// an upload, or one READ of a download, with completion-order replies, so
// that the replies to later requests on the same file overtake it. Each
// client must still transfer the file intact.
func TestClientsTolerateOutOfOrderReplies(t *testing.T) {
	data := randomBytes(4<<20 + 321)
	clients := []struct {
		name string
		// transfer uploads work/orders.csv to /orders.csv, or downloads
		// /orders.csv to work/orders.csv.
		transfer func(t *testing.T, srv *server, work string, upload bool)
	}{
		{name: "OpenSSH", transfer: transferWithOpenSSH},
		{name: "phpseclib", transfer: transferWithPhpseclib},
	}

	for _, c := range clients {
		for _, upload := range []bool{true, false} {
			name := c.name + map[bool]string{true: "/upload", false: "/download"}[upload]
			t.Run(name, func(t *testing.T) {
				hold := &firstReplyHold{write: upload}
				srv := startServer(t, proxied, sftpproxy.Options{Faults: hold.faults, ReplyOrder: sftpproxy.CompletionOrder})
				work := t.TempDir()
				source, result := filepath.Join(srv.files, "orders.csv"), filepath.Join(work, "orders.csv")
				if upload {
					source, result = result, source
				}
				writeFile(t, source, data)

				c.transfer(t, srv, work, upload)

				if got, err := os.ReadFile(result); err != nil || !bytes.Equal(got, data) {
					t.Errorf("transferred file differs from the original (%v)", err)
				}
				n := hold.overtaken()
				if n == 0 {
					t.Error("no reply overtook the held one, so the test proved nothing")
				}
				t.Logf("%d replies overtook the held one", n)
			})
		}
	}
}

func transferWithOpenSSH(t *testing.T, srv *server, work string, upload bool) {
	t.Helper()
	sftpPath := openSSHOrSkip(t)
	batch := "get /orders.csv orders.csv\n"
	if upload {
		batch = "put orders.csv /orders.csv\n"
	}
	if out, err := openSSH(t, sftpPath, srv, work, batch); err != nil {
		t.Fatalf("sftp failed: %v\n%s", err, out)
	}
}

func transferWithPhpseclib(t *testing.T, srv *server, work string, upload bool) {
	t.Helper()
	php := phpseclibOrSkip(t)
	op := "get"
	if upload {
		op = "put"
	}
	transcript := runPhpseclib(t, php, srv, "transfer.php", work, op)
	if results(t, transcript)[op] != true {
		t.Fatalf("phpseclib %s failed: %v", op, transcript)
	}
}

// firstReplyHold delays the reply to the first WRITE, or READ, at or beyond
// heldOffset on /orders.csv, and counts the requests on that file that
// arrive while the reply is held. Their replies overtake it.
type firstReplyHold struct {
	write bool

	mu         sync.Mutex
	heldAt     time.Time
	overtaking int
}

func (h *firstReplyHold) faults(r sftpproxy.Request) sftpproxy.Action {
	if r.Path != "/orders.csv" {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.heldAt.IsZero() && h.reachesHeldOffset(r.Packet) {
		h.heldAt = time.Now()
		return sftpproxy.Delay{When: sftpproxy.After, Duration: replyHold}
	}
	if !h.heldAt.IsZero() && time.Since(h.heldAt) < replyHold {
		h.overtaking++
	}
	return nil
}

func (h *firstReplyHold) reachesHeldOffset(p sftpwire.Packet) bool {
	switch p := p.(type) {
	case *sftpwire.Write:
		return h.write && p.Offset >= heldOffset
	case *sftpwire.Read:
		return !h.write && p.Offset >= heldOffset
	}
	return false
}

func (h *firstReplyHold) overtaken() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.overtaking
}
