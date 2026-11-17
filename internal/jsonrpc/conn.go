// Package jsonrpc implements the JSON-RPC 2.0 message layer shared by the
// stdio servers: Content-Length framed messages as used by the Language
// Server Protocol, and newline-delimited messages as used by the Model
// Context Protocol stdio transport.
package jsonrpc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// maxMessageSize bounds a single message so that a malformed header cannot
// make the server allocate without limit.
const maxMessageSize = 64 << 20

// Message is a request, a notification or a response. A request has an ID
// and a method, a notification only a method.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// IsRequest reports whether the message expects a response.
func (m *Message) IsRequest() bool { return m.Method != "" && len(m.ID) > 0 && string(m.ID) != "null" }

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message) }

// Errorf returns an Error with the given code.
func Errorf(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Framing selects how messages are delimited.
type Framing int

const (
	// Headers frames each message with a Content-Length header.
	Headers Framing = iota
	// Lines writes one JSON message per line. When reading, a message that
	// starts with a Content-Length header is accepted too, and replies switch
	// to header framing.
	Lines
)

// Conn reads and writes messages. Writes are serialized, so notifications
// may be sent from other goroutines while the read loop runs.
type Conn struct {
	r       *bufio.Reader
	mu      sync.Mutex
	w       io.Writer
	framing Framing
}

// NewConn returns a connection reading from r and writing to w.
func NewConn(r io.Reader, w io.Writer, framing Framing) *Conn {
	return &Conn{r: bufio.NewReaderSize(r, 64*1024), w: w, framing: framing}
}

// Read returns the next message. Blank lines between line-delimited messages
// are skipped. A message that is not valid JSON is returned as an *Error with
// CodeParseError so that the caller can reply and continue.
func (c *Conn) Read() (*Message, error) {
	data, err := c.readFrame()
	if err != nil {
		return nil, err
	}
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, Errorf(CodeParseError, "parse error: %v", err)
	}
	if msg.JSONRPC != "2.0" {
		return &msg, Errorf(CodeInvalidRequest, "jsonrpc must be \"2.0\"")
	}
	return &msg, nil
}

func (c *Conn) readFrame() ([]byte, error) {
	for {
		line, err := c.r.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if err != nil && (err != io.EOF || trimmed == "") {
			return nil, err
		}
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(strings.ToLower(trimmed), "content-length:"):
			return c.readBody(trimmed)
		case c.framing == Headers:
			return nil, fmt.Errorf("expected Content-Length header, got %q", trimmed)
		}
		return []byte(trimmed), nil
	}
}

// readBody reads the remaining headers after the Content-Length line and
// then the body.
func (c *Conn) readBody(header string) ([]byte, error) {
	n, err := strconv.Atoi(strings.TrimSpace(header[len("content-length:"):]))
	if err != nil || n < 0 || n > maxMessageSize {
		return nil, fmt.Errorf("invalid Content-Length header %q", header)
	}
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.framing = Headers
	c.mu.Unlock()
	return body, nil
}

// Reply sends a successful response. A nil result is sent as null.
func (c *Conn) Reply(id json.RawMessage, result any) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return c.write(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{"2.0", id, data})
}

// ReplyError sends an error response. A missing ID is sent as null.
func (c *Conn) ReplyError(id json.RawMessage, e *Error) error {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return c.write(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   *Error          `json:"error"`
	}{"2.0", id, e})
}

// Notify sends a notification.
func (c *Conn) Notify(method string, params any) error {
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return c.write(Message{JSONRPC: "2.0", Method: method, Params: data})
}

func (c *Conn) write(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var buf bytes.Buffer
	if c.framing == Headers {
		fmt.Fprintf(&buf, "Content-Length: %d\r\n\r\n", len(data))
		buf.Write(data)
	} else {
		buf.Write(data)
		buf.WriteByte('\n')
	}
	_, err = c.w.Write(buf.Bytes())
	return err
}

// IsParseError reports whether err is a recoverable message error returned
// by Read, after which the connection can still be used.
func IsParseError(err error) bool {
	var e *Error
	return errors.As(err, &e)
}
