package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/nebarg/sftpit/internal/runs"
)

// Client calls the control API.
type Client struct {
	// Addr is the API's host and port, such as 127.0.0.1:8122.
	Addr string
}

// httpClient gives up on a request only once a reset still waiting for its
// sessions would have failed, so that a reset's own failure is reported.
var httpClient = &http.Client{Timeout: resetTimeout + 30*time.Second}

// Error is a request that the control API refused or failed.
type Error struct {
	// StatusCode is the HTTP status of the reply, and Message the error it
	// gave.
	StatusCode int
	Message    string
}

func (e *Error) Error() string { return e.Message }

// Status returns the status of the server and its current run.
func (c *Client) Status(ctx context.Context) (Status, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+c.Addr+"/api/v1/status", nil)
	if err != nil {
		return Status{}, fmt.Errorf("control: status: %w", err)
	}
	var status Status
	if err := send(httpClient, req, &status); err != nil {
		return Status{}, err
	}
	return status, nil
}

// Assert asks the server to drain run, waiting for up to timeout for its
// file handles to close, and returns the verdict on it. A run that fails is
// not an error, but one the API refuses or fails is an *Error.
func (c *Client) Assert(ctx context.Context, run string, timeout time.Duration) (runs.Report, error) {
	b, err := json.Marshal(DrainRequest{Timeout: timeout.String()})
	if err != nil {
		return runs.Report{}, fmt.Errorf("control: assert: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+c.Addr+"/api/v1/runs/"+url.PathEscape(run)+"/assert", bytes.NewReader(b))
	if err != nil {
		return runs.Report{}, fmt.Errorf("control: assert: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(RequestHeader, "1")
	var report runs.Report
	waiting := &http.Client{Timeout: timeout + httpClient.Timeout}
	if err := send(waiting, req, &report); err != nil {
		return runs.Report{}, err
	}
	return report, nil
}

// Reset asks the server to end its current run and start the one req
// chooses, and returns the status of the run it started. A reset the API
// refuses or fails is an *Error.
func (c *Client) Reset(ctx context.Context, req ResetRequest) (Status, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return Status{}, fmt.Errorf("control: reset: %w", err)
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+c.Addr+"/api/v1/reset", bytes.NewReader(b))
	if err != nil {
		return Status{}, fmt.Errorf("control: reset: %w", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set(RequestHeader, "1")
	var status Status
	if err := send(httpClient, hreq, &status); err != nil {
		return Status{}, err
	}
	return status, nil
}

// send sends req with client and decodes its reply into v, or returns the
// API's error as it is.
func send(client *http.Client, req *http.Request, v any) error {
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var reply struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil || reply.Error == "" {
			reply.Error = resp.Status
		}
		return &Error{StatusCode: resp.StatusCode, Message: reply.Error}
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("control: read the reply to %s %s: %w", req.Method, req.URL.Path, err)
	}
	return nil
}
