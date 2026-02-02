// Package api provides HTTP handlers for the API server.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// DeploymentEvent represents an event sent to the callback URL during deployment.
type DeploymentEvent struct {
	DeploymentID string `json:"deployment_id,omitempty"`
	Level        string `json:"level,omitempty"`
	Step         string `json:"step,omitempty"`
	Phase        string `json:"phase,omitempty"`
	Message      string `json:"message,omitempty"`
	Status       string `json:"status,omitempty"`
	Error        string `json:"error,omitempty"`
}

// CallbackEmitter sends deployment events to a callback URL.
type CallbackEmitter struct {
	callbackURL  string
	deploymentID string
	apiKey       string
	client       *http.Client
}

// NewCallbackEmitter creates a new CallbackEmitter.
// Returns nil if callbackURL is empty.
// The API key is read from MITHLOND_API_KEY environment variable.
func NewCallbackEmitter(callbackURL, deploymentID string) *CallbackEmitter {
	if callbackURL == "" {
		return nil
	}
	apiKey := os.Getenv("MITHLOND_API_KEY")
	return &CallbackEmitter{
		callbackURL:  callbackURL,
		deploymentID: deploymentID,
		apiKey:       apiKey,
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

// Emit sends an event to the callback URL.
func (e *CallbackEmitter) Emit(ctx context.Context, event DeploymentEvent) {
	if e == nil {
		return
	}

	event.DeploymentID = e.deploymentID

	payload, err := json.Marshal(event)
	if err != nil {
		slog.Error("failed to marshal callback event", "error", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.callbackURL, bytes.NewReader(payload))
	if err != nil {
		slog.Error("failed to create callback request", "error", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", e.apiKey)

	resp, err := e.client.Do(req)
	if err != nil {
		slog.Error("failed to send callback event", "error", err, "url", e.callbackURL)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Warn("callback returned error status", "status", resp.StatusCode, "url", e.callbackURL)
	}
}

// EmitStart sends a step start event.
func (e *CallbackEmitter) EmitStart(ctx context.Context, step, message string) {
	e.Emit(ctx, DeploymentEvent{
		Level:   "info",
		Step:    step,
		Phase:   "start",
		Message: message,
	})
}

// EmitDone sends a step done event.
func (e *CallbackEmitter) EmitDone(ctx context.Context, step, message string) {
	e.Emit(ctx, DeploymentEvent{
		Level:   "info",
		Step:    step,
		Phase:   "done",
		Message: message,
	})
}

// EmitCompleted sends the final completed status event.
func (e *CallbackEmitter) EmitCompleted(ctx context.Context, message string) {
	e.Emit(ctx, DeploymentEvent{
		Level:   "info",
		Phase:   "done",
		Message: message,
		Status:  "completed",
	})
}

// EmitFailed sends a failed status event with error details.
func (e *CallbackEmitter) EmitFailed(ctx context.Context, step string, err error) {
	e.Emit(ctx, DeploymentEvent{
		Level:   "error",
		Step:    step,
		Phase:   "done",
		Message: fmt.Sprintf("Deployment failed: %v", err),
		Status:  "failed",
		Error:   err.Error(),
	})
}
