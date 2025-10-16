package audit

import (
	"context"
	"fmt"
	"time"
)

// Manager provides a high-level interface for audit logging
type Manager struct {
	writer *Writer
	reader *Reader
}

// ManagerConfig holds configuration for the audit manager
type ManagerConfig struct {
	BasePath      string
	BatchSize     int
	FlushInterval time.Duration
	MaxFileSize   int64
}

// NewManager creates a new audit log manager
func NewManager(config ManagerConfig) (*Manager, error) {
	// Create writer
	writer, err := NewWriter(WriterConfig{
		BasePath:      config.BasePath,
		BatchSize:     config.BatchSize,
		FlushInterval: config.FlushInterval,
		MaxFileSize:   config.MaxFileSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create writer: %w", err)
	}

	// Create reader
	reader, err := NewReader(config.BasePath)
	if err != nil {
		writer.Close()
		return nil, fmt.Errorf("failed to create reader: %w", err)
	}

	return &Manager{
		writer: writer,
		reader: reader,
	}, nil
}

// Log writes an audit log entry
func (m *Manager) Log(ctx context.Context, log *AuditLog) error {
	return m.writer.Write(log)
}

// LogEvent is a convenience method for logging events
func (m *Manager) LogEvent(ctx context.Context, event EventBuilder) error {
	log := event.Build()
	return m.writer.Write(log)
}

// Query retrieves audit logs matching the filter
func (m *Manager) Query(ctx context.Context, filter QueryFilter) ([]*AuditLog, error) {
	return m.reader.Query(filter)
}

// GetByID retrieves a single audit log by ID
func (m *Manager) GetByID(ctx context.Context, id string) (*AuditLog, error) {
	return m.reader.GetByID(id)
}

// Flush forces a flush of buffered entries
func (m *Manager) Flush() error {
	return m.writer.Flush()
}

// Close gracefully shuts down the manager
func (m *Manager) Close() error {
	if err := m.writer.Close(); err != nil {
		return err
	}
	return m.reader.Close()
}

// Stats returns combined statistics
func (m *Manager) Stats() ManagerStats {
	return ManagerStats{
		WriterStats: m.writer.Stats(),
		ReaderStats: m.reader.Stats(),
	}
}

// ManagerStats holds combined statistics
type ManagerStats struct {
	WriterStats WriterStats
	ReaderStats ReaderStats
}

// EventBuilder helps build audit log entries
type EventBuilder struct {
	log *AuditLog
}

// NewEventBuilder creates a new event builder
func NewEventBuilder() *EventBuilder {
	return &EventBuilder{
		log: &AuditLog{
			CreatedAt: time.Now().UTC(),
		},
	}
}

// WithTenantID sets the tenant ID
func (b *EventBuilder) WithTenantID(tenantID string) *EventBuilder {
	b.log.TenantID = &tenantID
	return b
}

// WithEventType sets the event type
func (b *EventBuilder) WithEventType(eventType string) *EventBuilder {
	b.log.EventType = eventType
	return b
}

// WithActor sets the actor information
func (b *EventBuilder) WithActor(actorID, actorEmail string) *EventBuilder {
	b.log.ActorID = actorID
	b.log.ActorEmail = actorEmail
	return b
}

// WithTarget sets the target information
func (b *EventBuilder) WithTarget(targetType, targetID string) *EventBuilder {
	b.log.TargetType = targetType
	b.log.TargetID = targetID
	return b
}

// WithAction sets the action
func (b *EventBuilder) WithAction(action string) *EventBuilder {
	b.log.Action = action
	return b
}

// WithResult sets the result
func (b *EventBuilder) WithResult(result string) *EventBuilder {
	b.log.Result = result
	return b
}

// WithError sets the error message
func (b *EventBuilder) WithError(err error) *EventBuilder {
	if err != nil {
		b.log.ErrorMessage = err.Error()
		b.log.Result = ResultFailure
	}
	return b
}

// WithBeforeState sets the before state
func (b *EventBuilder) WithBeforeState(state map[string]interface{}) *EventBuilder {
	b.log.BeforeState = state
	return b
}

// WithAfterState sets the after state
func (b *EventBuilder) WithAfterState(state map[string]interface{}) *EventBuilder {
	b.log.AfterState = state
	return b
}

// WithRequest sets request information
func (b *EventBuilder) WithRequest(ipAddress, userAgent, requestID string) *EventBuilder {
	b.log.IPAddress = ipAddress
	b.log.UserAgent = userAgent
	b.log.RequestID = requestID
	return b
}

// WithMetadata adds metadata
func (b *EventBuilder) WithMetadata(metadata map[string]interface{}) *EventBuilder {
	b.log.Metadata = metadata
	return b
}

// Build returns the constructed audit log
func (b *EventBuilder) Build() *AuditLog {
	return b.log
}
