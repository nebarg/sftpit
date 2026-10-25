package backend

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

var errServerEnded = errors.New("backend: request server ended the session")

// relayInOrder passes each request from client to server, which serves the
// session with h, and waits for its reply before passing the next. Every
// request gets exactly one reply, and a status reply carries OpenSSH's
// message for its code, in place of pkg/sftp's, which can be empty or name a
// file by its name on the host.
func relayInOrder(client, server io.ReadWriter, h *handler) error {
	fromClient, fromServer := bufio.NewReader(client), bufio.NewReader(server)
	g := &guard{handles: make(map[string]handleKind), handler: h}
	for {
		request, err := sftpwire.ReadPacket(fromClient, maxPacketLength)
		if err != nil {
			return err
		}
		reply, err := g.serve(request, func(request []byte) ([]byte, error) {
			if err := writePacket(server, request); err != nil {
				return nil, errServerEnded
			}
			reply, err := sftpwire.ReadPacket(fromServer, maxPacketLength)
			if err != nil {
				return nil, errServerEnded
			}
			return withOpenSSHMessage(reply), nil
		})
		if err != nil {
			return err
		}
		if err := writePacket(client, reply); err != nil {
			return err
		}
	}
}

func writePacket(w io.Writer, body []byte) error {
	b := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(body)), uint32(len(body)))
	_, err := w.Write(append(b, body...))
	return err
}

// guard keeps from pkg/sftp's request server the requests that do not suit
// their handle, and answers them as OpenSSH's sftp-server does. pkg/sftp
// serves a request by how its handle was opened rather than by what it
// asks, so it would serve a READ on a handle open only for writing by
// writing the read buffer to the file, and a WRITE on one open only for
// reading with the file's data. The guard also gives the handler the
// permissions that pkg/sftp loses from an OPEN or MKDIR.
type guard struct {
	handles map[string]handleKind
	handler *handler
}

// handleKind is what a handle was opened as, which decides the requests it
// can serve.
type handleKind struct {
	dir      bool
	readable bool
	writable bool
}

// serve answers request itself if its handle cannot serve it, and otherwise
// has forward pass it on, as pkg/sftp should see it, and returns the reply.
func (g *guard) serve(request []byte, forward func([]byte) ([]byte, error)) ([]byte, error) {
	id, p, err := sftpwire.DecodeRequest(request)
	if err != nil {
		return forward(request)
	}
	if code := g.refusal(p); code != sftpwire.StatusOK {
		return statusPacket(id, code), nil
	}
	switch p := p.(type) {
	case *sftpwire.Open:
		// OpenSSH opens a file for reading when an OPEN asks neither to
		// read nor to write, where pkg/sftp would refuse it or serve its
		// reads by writing.
		if p.Flags&(sftpwire.OpenRead|sftpwire.OpenWrite) == 0 {
			p.Flags |= sftpwire.OpenRead
			request = sftpwire.AppendPacket(nil, id, p)[4:]
		}
		g.handler.perm = requestedPerm(p.Attrs, 0o666)
	case *sftpwire.Mkdir:
		g.handler.perm = requestedPerm(p.Attrs, 0o777)
	case *sftpwire.FSetStat:
		if kind, open := g.handles[p.Handle]; open && !kind.writable && p.Attrs.Flags&sftpwire.AttrSize != 0 {
			return g.setStatReadOnly(id, p, forward)
		}
	}
	reply, err := forward(request)
	if err == nil {
		g.observe(p, reply)
	}
	return reply, err
}

// setStatReadOnly serves p, an FSETSTAT that sets the size through a handle
// open only for reading. pkg/sftp would truncate the file by its path,
// whatever the handle allows. OpenSSH's ftruncate on the handle's descriptor
// fails with EINVAL instead, which it answers with SSH_FX_BAD_MESSAGE unless
// setting another attribute fails after it, and it still sets the others.
func (g *guard) setStatReadOnly(id uint32, p *sftpwire.FSetStat, forward func([]byte) ([]byte, error)) ([]byte, error) {
	p.Attrs.Flags &^= sftpwire.AttrSize
	reply, err := forward(sftpwire.AppendPacket(nil, id, p)[4:])
	if err != nil {
		return nil, err
	}
	if _, r, err := sftpwire.DecodeReply(reply); err == nil {
		if st, ok := r.(*sftpwire.StatusReply); ok && st.Code == sftpwire.StatusOK {
			return statusPacket(id, sftpwire.StatusBadMessage), nil
		}
	}
	return reply, nil
}

// requestedPerm returns the permissions attrs ask for a new file or
// directory, or def if they ask for none, as OpenSSH's sftp-server does.
func requestedPerm(attrs sftpwire.Attrs, def os.FileMode) os.FileMode {
	if attrs.Flags&sftpwire.AttrPermissions == 0 {
		return def
	}
	return permissions(attrs.Permissions)
}

// refusal returns the status OpenSSH answers p with when p's handle cannot
// serve it, or SSH_FX_OK. A request on a handle that is not open is passed
// on, except CLOSE: pkg/sftp answers the others with SSH_FX_FAILURE, as
// OpenSSH does, but CLOSE with SSH_FX_FAILURE too, where OpenSSH answers
// SSH_FX_NO_SUCH_FILE.
func (g *guard) refusal(p sftpwire.Packet) sftpwire.StatusCode {
	var handle string
	switch p := p.(type) {
	case *sftpwire.Close:
		if _, open := g.handles[p.Handle]; !open {
			return sftpwire.StatusNoSuchFile
		}
		return sftpwire.StatusOK
	case *sftpwire.Read:
		handle = p.Handle
	case *sftpwire.Write:
		handle = p.Handle
	case *sftpwire.FStat:
		handle = p.Handle
	case *sftpwire.FSetStat:
		handle = p.Handle
	case *sftpwire.ReadDir:
		handle = p.Handle
	default:
		return sftpwire.StatusOK
	}
	kind, open := g.handles[handle]
	if !open {
		return sftpwire.StatusOK
	}
	return kind.refusal(p)
}

// refusal returns the status OpenSSH answers p with on a handle of kind k,
// or SSH_FX_OK if the handle can serve it. A directory handle has no
// descriptor to read, write or stat through, and a file descriptor fails a
// read or write that its open did not allow with EBADF.
func (k handleKind) refusal(p sftpwire.Packet) sftpwire.StatusCode {
	_, readdir := p.(*sftpwire.ReadDir)
	_, read := p.(*sftpwire.Read)
	_, write := p.(*sftpwire.Write)
	switch {
	case readdir != k.dir:
		return sftpwire.StatusFailure
	case read && !k.readable, write && !k.writable:
		return sftpwire.StatusNoSuchFile
	}
	return sftpwire.StatusOK
}

// observe records the handle that reply opens for request p, and forgets
// the one a CLOSE closes, as both servers do whether or not the close
// succeeds.
func (g *guard) observe(p sftpwire.Packet, reply []byte) {
	var kind handleKind
	switch p := p.(type) {
	case *sftpwire.Close:
		delete(g.handles, p.Handle)
		return
	case *sftpwire.Open:
		kind = handleKind{readable: p.Flags&sftpwire.OpenRead != 0, writable: p.Flags&sftpwire.OpenWrite != 0}
	case *sftpwire.OpenDir:
		kind = handleKind{dir: true}
	default:
		return
	}
	if _, r, err := sftpwire.DecodeReply(reply); err == nil {
		if h, ok := r.(*sftpwire.HandleReply); ok {
			g.handles[h.Handle] = kind
		}
	}
}

// withOpenSSHMessage gives a status reply the message OpenSSH's sftp-server
// sends with its code.
func withOpenSSHMessage(reply []byte) []byte {
	if sftpwire.PacketType(reply[0]) != sftpwire.TypeStatus {
		return reply
	}
	id, p, err := sftpwire.DecodeReply(reply)
	if err != nil {
		return reply
	}
	return statusPacket(id, p.(*sftpwire.StatusReply).Code)
}

func statusPacket(id uint32, code sftpwire.StatusCode) []byte {
	return sftpwire.AppendPacket(nil, id, &sftpwire.StatusReply{Code: code, Message: code.Message()})[4:]
}
