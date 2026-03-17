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

package writers

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HttpPostWriter writes output by POSTing JSON data to an HTTP endpoint.
type HttpPostWriter struct {
	endpoint string
	client   *http.Client
	mu       sync.Mutex
	closed   bool
}

// NewHttpPostWriter creates a new HTTP POST writer targeting the given endpoint URL.
func NewHttpPostWriter(endpoint string) (*HttpPostWriter, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("HTTP endpoint cannot be empty")
	}

	return &HttpPostWriter{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// Write sends the data as a JSON POST request to the configured endpoint.
func (w *HttpPostWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return 0, fmt.Errorf("writer is closed")
	}
	w.mu.Unlock()

	resp, err := w.client.Post(w.endpoint, "application/json", bytes.NewReader(p))
	if err != nil {
		return 0, fmt.Errorf("HTTP POST to %s failed: %w", w.endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return len(p), fmt.Errorf("HTTP POST to %s returned status %d", w.endpoint, resp.StatusCode)
	}

	return len(p), nil
}

// Close marks the writer as closed.
func (w *HttpPostWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

// Name returns the writer name.
func (w *HttpPostWriter) Name() string {
	return w.endpoint
}

// Flush is a no-op since each Write performs an immediate HTTP POST.
func (w *HttpPostWriter) Flush() error {
	return nil
}
