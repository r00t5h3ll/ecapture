// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/output/writers"
)

// TLSDataEvent is the interface that TLS data events must satisfy
// for the HarHandler to process them.
type TLSDataEvent interface {
	GetData() []byte
	GetDataLen() uint32
	GetPid() uint32
	GetFd() uint32
	IsRead() bool
}

// HAR format structures matching the server's /adr/har endpoint.
type harEntry struct {
	Request  harRequest  `json:"request"`
	Response harResponse `json:"response"`
}

type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	Headers     []harNameValue `json:"headers"`
	QueryString []harNameValue `json:"queryString"`
	PostData    *harPostData   `json:"postData,omitempty"`
	Cookies     []string       `json:"cookies"`
}

type harResponse struct {
	Status  int            `json:"status"`
	Headers []harNameValue `json:"headers"`
	Content *harContent    `json:"content,omitempty"`
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
}

type harContent struct {
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
}

type sessionState int

const (
	stateInit sessionState = iota
	stateReqAccumulating
	stateRespAccumulating
)

const (
	maxSessionBufSize  = 10 * 1024 * 1024 // 10MB max per buffer
	sessionFlushPeriod = 5 * time.Second
)

type httpSession struct {
	reqBuf   bytes.Buffer
	respBuf  bytes.Buffer
	state    sessionState
	lastSeen time.Time
}

// HarHandler correlates TLS read/write events into HTTP request/response pairs,
// builds HAR entries, filters by host, and writes JSON to the output writer.
type HarHandler struct {
	writer     writers.OutputWriter
	filterHost string
	sessions   map[string]*httpSession
	mu         sync.Mutex
	done       chan struct{}
}

// NewHarHandler creates a new HarHandler.
// filterHost filters HTTP requests by Host header (empty means no filtering).
func NewHarHandler(writer writers.OutputWriter, filterHost string) *HarHandler {
	h := &HarHandler{
		writer:     writer,
		filterHost: strings.ToLower(filterHost),
		sessions:   make(map[string]*httpSession),
		done:       make(chan struct{}),
	}
	go h.flushLoop()
	return h
}

// Handle processes a TLS data event, correlating request/response by pid:fd.
func (h *HarHandler) Handle(event domain.Event) error {
	if event == nil {
		return nil
	}

	tlsEvent, ok := event.(TLSDataEvent)
	if !ok {
		return nil // Not a TLS data event (e.g., connect event), skip
	}

	data := tlsEvent.GetData()
	if len(data) == 0 {
		return nil
	}

	key := fmt.Sprintf("%d:%d", tlsEvent.GetPid(), tlsEvent.GetFd())

	h.mu.Lock()
	defer h.mu.Unlock()

	session, exists := h.sessions[key]
	if !exists {
		session = &httpSession{}
		h.sessions[key] = session
	}
	session.lastSeen = time.Now()

	if tlsEvent.IsRead() {
		// Response data
		if session.respBuf.Len()+len(data) > maxSessionBufSize {
			// Buffer overflow protection: emit what we have and reset
			h.emitLocked(key, session)
			session = &httpSession{lastSeen: time.Now()}
			h.sessions[key] = session
			return nil
		}
		session.respBuf.Write(data)
		session.state = stateRespAccumulating
	} else {
		// Request data (SSL_write)
		if session.state == stateRespAccumulating && session.respBuf.Len() > 0 {
			// New request starting while we have accumulated response data.
			// This means the previous response is complete — emit the pair.
			h.emitLocked(key, session)
			session = &httpSession{lastSeen: time.Now()}
			h.sessions[key] = session
		}
		if session.reqBuf.Len()+len(data) > maxSessionBufSize {
			return nil
		}
		session.reqBuf.Write(data)
		session.state = stateReqAccumulating
	}

	return nil
}

// emitLocked builds a HarEntry from the session's buffers and writes it.
// Must be called with h.mu held.
func (h *HarHandler) emitLocked(key string, session *httpSession) {
	if session.reqBuf.Len() == 0 && session.respBuf.Len() == 0 {
		return
	}

	entry, err := h.buildHarEntry(session)
	if err != nil {
		// Parsing failed; discard this session data silently
		return
	}

	// Host filter
	if h.filterHost != "" {
		reqURL, parseErr := url.Parse(entry.Request.URL)
		if parseErr != nil {
			return
		}
		if strings.ToLower(reqURL.Host) != h.filterHost {
			return
		}
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return
	}

	// Async POST to avoid blocking event processing
	go func(data []byte) {
		_, _ = h.writer.Write(data)
	}(jsonData)
}

// buildHarEntry parses HTTP request and response from session buffers.
func (h *HarHandler) buildHarEntry(session *httpSession) (*harEntry, error) {
	entry := &harEntry{}

	// Parse HTTP request
	if session.reqBuf.Len() > 0 {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(session.reqBuf.Bytes())))
		if err != nil {
			return nil, fmt.Errorf("parse request: %w", err)
		}
		defer req.Body.Close()

		// Build full URL
		scheme := "https"
		host := req.Host
		fullURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

		// Parse query string
		parsedURL, _ := url.Parse(fullURL)
		var queryString []harNameValue
		if parsedURL != nil {
			for k, vs := range parsedURL.Query() {
				for _, v := range vs {
					queryString = append(queryString, harNameValue{Name: k, Value: v})
				}
			}
		}

		// Headers
		var headers []harNameValue
		for name, values := range req.Header {
			for _, v := range values {
				headers = append(headers, harNameValue{Name: name, Value: v})
			}
		}

		entry.Request = harRequest{
			Method:      req.Method,
			URL:         fullURL,
			Headers:     headers,
			QueryString: queryString,
			Cookies:     []string{},
		}

		// Request body
		body, _ := io.ReadAll(req.Body)
		if len(body) > 0 {
			entry.Request.PostData = &harPostData{
				Text: string(body),
			}
		}
	}

	// Parse HTTP response
	if session.respBuf.Len() > 0 {
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(session.respBuf.Bytes())), nil)
		if err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		defer resp.Body.Close()

		var respHeaders []harNameValue
		for name, values := range resp.Header {
			for _, v := range values {
				respHeaders = append(respHeaders, harNameValue{Name: name, Value: v})
			}
		}

		entry.Response = harResponse{
			Status:  resp.StatusCode,
			Headers: respHeaders,
		}

		// Response body: base64 encode the raw bytes (preserves binary/encrypted content)
		respBody, _ := io.ReadAll(resp.Body)
		if len(respBody) > 0 {
			entry.Response.Content = &harContent{
				Text:     base64.StdEncoding.EncodeToString(respBody),
				Encoding: "base64",
			}
		}
	}

	return entry, nil
}

// flushLoop periodically emits sessions that have been idle (in response-accumulating state).
func (h *HarHandler) flushLoop() {
	ticker := time.NewTicker(sessionFlushPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			h.flushStaleSessions()
		}
	}
}

// flushStaleSessions emits and removes sessions idle for longer than sessionFlushPeriod.
func (h *HarHandler) flushStaleSessions() {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	for key, session := range h.sessions {
		if session.state == stateRespAccumulating && now.Sub(session.lastSeen) > sessionFlushPeriod {
			h.emitLocked(key, session)
			delete(h.sessions, key)
		}
		// Also clean up very old sessions in any state
		if now.Sub(session.lastSeen) > 30*time.Second {
			delete(h.sessions, key)
		}
	}
}

// Name returns the handler's identifier.
func (h *HarHandler) Name() string {
	return ModeHar
}

// Writer returns the associated output writer.
func (h *HarHandler) Writer() writers.OutputWriter {
	return h.writer
}

// Close stops the flush loop and releases resources.
func (h *HarHandler) Close() error {
	close(h.done)

	// Emit any remaining sessions
	h.mu.Lock()
	for key, session := range h.sessions {
		h.emitLocked(key, session)
		delete(h.sessions, key)
	}
	h.mu.Unlock()

	return h.writer.Close()
}
