package notcodersdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/xerrors"
)

const (
	SessionTokenHeader = "Coder-Session-Token"
)

type AgentSubsystem string

const (
	AgentSubsystemEnvbuilder AgentSubsystem = "envbuilder"
)

// ExternalLogSourceID is the statically-defined ID of a log-source that
// appears as "External" in the dashboard.
//
// This is to support legacy API-consumers that do not create their own
// log-source. This should be removed in the future.
var ExternalLogSourceID = uuid.MustParse("3b579bf4-1ed8-4b99-87a8-e9a1e3410410")

type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

type Log struct {
	CreatedAt time.Time `json:"created_at"`
	Output    string    `json:"output"`
	Level     LogLevel  `json:"level"`
}

type PatchLogs struct {
	LogSourceID uuid.UUID `json:"log_source_id"`
	Logs        []Log     `json:"logs"`
}

// New returns a client that is used to interact with the
// Coder API from a workspace agent.
func New(serverURL *url.URL) *Client {
	return &Client{
		URL:        serverURL,
		HTTPClient: &http.Client{},
	}
}

// Client wraps `notcodersdk.Client` with specific functions
// scoped to a workspace agent.
type Client struct {
	// mu protects the fields sessionToken, logger, and logBodies. These
	// need to be safe for concurrent access.
	mu           sync.RWMutex
	sessionToken string
	logBodies    bool

	HTTPClient *http.Client
	URL        *url.URL

	// SessionTokenHeader is an optional custom header to use for setting tokens. By
	// default 'Coder-Session-Token' is used.
	SessionTokenHeader string

	// PlainLogger may be set to log HTTP traffic in a human-readable form.
	// It uses the LogBodies option.
	PlainLogger io.Writer
}

// SessionToken returns the currently set token for the client.
func (c *Client) SessionToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionToken
}

// SetSessionToken returns the currently set token for the client.
func (c *Client) SetSessionToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionToken = token
}

// PatchLogs writes log messages to the agent startup script.
// Log messages are limited to 1MB in total.
//
// Deprecated: use the DRPCAgentClient.BatchCreateLogs instead
func (c *Client) PatchLogs(ctx context.Context, req PatchLogs) error {
	res, err := c.Request(ctx, http.MethodPatch, "/api/v2/workspaceagents/me/logs", req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ReadBodyAsError(res)
	}
	return nil
}

// RequestOption is a function that can be used to modify an http.Request.
type RequestOption func(*http.Request)

// Request performs a HTTP request with the body provided. The caller is
// responsible for closing the response body.
func (c *Client) Request(ctx context.Context, method, path string, body interface{}, opts ...RequestOption) (*http.Response, error) {
	serverURL, err := c.URL.Parse(path)
	if err != nil {
		return nil, xerrors.Errorf("parse url: %w", err)
	}

	var r io.Reader
	if body != nil {
		switch data := body.(type) {
		case io.Reader:
			r = data
		case []byte:
			r = bytes.NewReader(data)
		default:
			// Assume JSON in all other cases.
			buf := bytes.NewBuffer(nil)
			enc := json.NewEncoder(buf)
			enc.SetEscapeHTML(false)
			err = enc.Encode(body)
			if err != nil {
				return nil, xerrors.Errorf("encode body: %w", err)
			}
			r = buf
		}
	}

	// Copy the request body so we can log it.
	var reqBody []byte
	c.mu.RLock()
	logBodies := c.logBodies
	c.mu.RUnlock()
	if r != nil && logBodies {
		reqBody, err = io.ReadAll(r)
		if err != nil {
			return nil, xerrors.Errorf("read request body: %w", err)
		}
		r = bytes.NewReader(reqBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, serverURL.String(), r)
	if err != nil {
		return nil, xerrors.Errorf("create request: %w", err)
	}

	tokenHeader := c.SessionTokenHeader
	if tokenHeader == "" {
		tokenHeader = SessionTokenHeader
	}
	req.Header.Set(tokenHeader, c.SessionToken())

	if r != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, opt := range opts {
		opt(req)
	}

	resp, err := c.HTTPClient.Do(req)

	// We log after sending the request because the HTTP Transport may modify
	// the request within Do, e.g. by adding headers.
	if resp != nil && c.PlainLogger != nil {
		out, err := httputil.DumpRequest(resp.Request, logBodies)
		if err != nil {
			return nil, xerrors.Errorf("dump request: %w", err)
		}
		out = prefixLines([]byte("http --> "), out)
		_, _ = c.PlainLogger.Write(out)
	}

	if err != nil {
		return nil, err
	}

	if c.PlainLogger != nil {
		out, err := httputil.DumpResponse(resp, logBodies)
		if err != nil {
			return nil, xerrors.Errorf("dump response: %w", err)
		}
		out = prefixLines([]byte("http <-- "), out)
		_, _ = c.PlainLogger.Write(out)
	}

	// Copy the response body so we can log it if it's a loggable mime type.
	var respBody []byte
	if resp.Body != nil && logBodies {
		mimeType := parseMimeType(resp.Header.Get("Content-Type"))
		if _, ok := loggableMimeTypes[mimeType]; ok {
			respBody, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, xerrors.Errorf("copy response body for logs: %w", err)
			}
			err = resp.Body.Close()
			if err != nil {
				return nil, xerrors.Errorf("close response body: %w", err)
			}
			resp.Body = io.NopCloser(bytes.NewReader(respBody))
		}
	}

	return resp, err
}

func parseMimeType(contentType string) string {
	mimeType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mimeType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	}

	return mimeType
}

// loggableMimeTypes is a list of MIME types that are safe to log
// the output of. This is useful for debugging or testing.
var loggableMimeTypes = map[string]struct{}{
	"application/json": {},
	"text/plain":       {},
	// lots of webserver error pages are HTML
	"text/html": {},
}

func prefixLines(prefix, s []byte) []byte {
	ss := bytes.NewBuffer(make([]byte, 0, len(s)*2))
	for _, line := range bytes.Split(s, []byte("\n")) {
		_, _ = ss.Write(prefix)
		_, _ = ss.Write(line)
		_ = ss.WriteByte('\n')
	}
	return ss.Bytes()
}

// ReadBodyAsError reads the response as a codersdk.Response, and
// wraps it in a codersdk.Error type for easy marshaling.
//
// This will always return an error, so only call it if the response failed
// your expectations. Usually via status code checking.
// nolint:staticcheck
func ReadBodyAsError(res *http.Response) error {
	if res == nil {
		return xerrors.Errorf("no body returned")
	}
	defer res.Body.Close()

	var requestMethod, requestURL string
	if res.Request != nil {
		requestMethod = res.Request.Method
		if res.Request.URL != nil {
			requestURL = res.Request.URL.String()
		}
	}

	var helpMessage string
	if res.StatusCode == http.StatusUnauthorized {
		// 401 means the user is not logged in
		// 403 would mean that the user is not authorized
		helpMessage = "Try logging in using 'coder login'."
	}

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return xerrors.Errorf("read body: %w", err)
	}

	if mimeErr := ExpectJSONMime(res); mimeErr != nil {
		if len(resp) > 2048 {
			resp = append(resp[:2048], []byte("...")...)
		}
		if len(resp) == 0 {
			resp = []byte("no response body")
		}
		return &Error{
			statusCode: res.StatusCode,
			method:     requestMethod,
			url:        requestURL,
			Response: Response{
				Message: mimeErr.Error(),
				Detail:  string(resp),
			},
			Helper: helpMessage,
		}
	}

	var m Response
	err = json.NewDecoder(bytes.NewBuffer(resp)).Decode(&m)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return &Error{
				statusCode: res.StatusCode,
				Response: Response{
					Message: "empty response body",
				},
				Helper: helpMessage,
			}
		}
		return xerrors.Errorf("decode body: %w", err)
	}
	if m.Message == "" {
		if len(resp) > 1024 {
			resp = append(resp[:1024], []byte("...")...)
		}
		m.Message = fmt.Sprintf("unexpected status code %d, response has no message", res.StatusCode)
		m.Detail = string(resp)
	}

	return &Error{
		Response:   m,
		statusCode: res.StatusCode,
		method:     requestMethod,
		url:        requestURL,
		Helper:     helpMessage,
	}
}

// Response represents a generic HTTP response.
type Response struct {
	// Message is an actionable message that depicts actions the request took.
	// These messages should be fully formed sentences with proper punctuation.
	// Examples:
	// - "A user has been created."
	// - "Failed to create a user."
	Message string `json:"message"`
	// Detail is a debug message that provides further insight into why the
	// action failed. This information can be technical and a regular golang
	// err.Error() text.
	// - "database: too many open connections"
	// - "stat: too many open files"
	Detail string `json:"detail,omitempty"`
	// Validations are form field-specific friendly error messages. They will be
	// shown on a form field in the UI. These can also be used to add additional
	// context if there is a set of errors in the primary 'Message'.
	Validations []ValidationError `json:"validations,omitempty"`
}

// ValidationError represents a scoped error to a user input.
type ValidationError struct {
	Field  string `json:"field" validate:"required"`
	Detail string `json:"detail" validate:"required"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("field: %s detail: %s", e.Field, e.Detail)
}

var _ error = (*ValidationError)(nil)

// Error represents an unaccepted or invalid request to the API.
// @typescript-ignore Error
type Error struct {
	Response

	statusCode int
	method     string
	url        string

	Helper string
}

func (e *Error) StatusCode() int {
	return e.statusCode
}

func (e *Error) Method() string {
	return e.method
}

func (e *Error) URL() string {
	return e.url
}

func (e *Error) Friendly() string {
	var sb strings.Builder
	_, _ = fmt.Fprintf(&sb, "%s. %s", strings.TrimSuffix(e.Message, "."), e.Helper)
	for _, err := range e.Validations {
		_, _ = fmt.Fprintf(&sb, "\n- %s: %s", err.Field, err.Detail)
	}
	return sb.String()
}

func (e *Error) Error() string {
	var builder strings.Builder
	if e.method != "" && e.url != "" {
		_, _ = fmt.Fprintf(&builder, "%v %v: ", e.method, e.url)
	}
	_, _ = fmt.Fprintf(&builder, "unexpected status code %d: %s", e.statusCode, e.Message)
	if e.Helper != "" {
		_, _ = fmt.Fprintf(&builder, ": %s", e.Helper)
	}
	if e.Detail != "" {
		_, _ = fmt.Fprintf(&builder, "\n\tError: %s", e.Detail)
	}
	for _, err := range e.Validations {
		_, _ = fmt.Fprintf(&builder, "\n\t%s: %s", err.Field, err.Detail)
	}
	return builder.String()
}

// ExpectJSONMime is a helper function that will assert the content type
// of the response is application/json.
func ExpectJSONMime(res *http.Response) error {
	contentType := res.Header.Get("Content-Type")
	mimeType := parseMimeType(contentType)
	if mimeType != "application/json" {
		return xerrors.Errorf("unexpected non-JSON response %q", contentType)
	}
	return nil
}
