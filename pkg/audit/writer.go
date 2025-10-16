package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
)

// Writer handles async batch writing of audit logs
type Writer struct {
	basePath      string
	batchSize     int
	flushInterval time.Duration
	maxFileSize   int64

	buffer       []*AuditLog
	bufferMu     sync.Mutex
	currentFile  *os.File
	currentSize  int64
	indexer      *Indexer
	stopCh       chan struct{}
	wg           sync.WaitGroup
	encoder      *msgpack.Encoder
}

// WriterConfig holds configuration for the audit writer
type WriterConfig struct {
	BasePath      string        // Base directory for audit logs
	BatchSize     int           // Number of entries to batch before flush
	FlushInterval time.Duration // Maximum time between flushes
	MaxFileSize   int64         // Maximum size of a single file before rotation
}

// NewWriter creates a new audit log writer
func NewWriter(config WriterConfig) (*Writer, error) {
	if config.BatchSize <= 0 {
		config.BatchSize = 100
	}
	if config.FlushInterval <= 0 {
		config.FlushInterval = 5 * time.Second
	}
	if config.MaxFileSize <= 0 {
		config.MaxFileSize = 100 * 1024 * 1024 // 100MB
	}

	// Ensure base directory exists
	if err := os.MkdirAll(config.BasePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	indexer, err := NewIndexer(config.BasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create indexer: %w", err)
	}

	w := &Writer{
		basePath:      config.BasePath,
		batchSize:     config.BatchSize,
		flushInterval: config.FlushInterval,
		maxFileSize:   config.MaxFileSize,
		buffer:        make([]*AuditLog, 0, config.BatchSize),
		indexer:       indexer,
		stopCh:        make(chan struct{}),
	}

	// Open initial file
	if err := w.rotateFile(); err != nil {
		return nil, fmt.Errorf("failed to create initial audit log file: %w", err)
	}

	// Start background flusher
	w.wg.Add(1)
	go w.flushLoop()

	return w, nil
}

// Write adds an audit log entry to the buffer
func (w *Writer) Write(log *AuditLog) error {
	// Generate ID if not set
	if log.ID == "" {
		log.ID = uuid.New().String()
	}

	// Set timestamp if not set
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}

	w.bufferMu.Lock()
	w.buffer = append(w.buffer, log)
	shouldFlush := len(w.buffer) >= w.batchSize
	w.bufferMu.Unlock()

	// Flush if buffer is full
	if shouldFlush {
		return w.Flush()
	}

	return nil
}

// Flush writes all buffered entries to disk
func (w *Writer) Flush() error {
	w.bufferMu.Lock()
	if len(w.buffer) == 0 {
		w.bufferMu.Unlock()
		return nil
	}

	// Take ownership of current buffer
	toWrite := w.buffer
	w.buffer = make([]*AuditLog, 0, w.batchSize)
	w.bufferMu.Unlock()

	// Write entries
	for _, log := range toWrite {
		if err := w.writeEntry(log); err != nil {
			return fmt.Errorf("failed to write audit log: %w", err)
		}
	}

	// Sync to disk
	if w.currentFile != nil {
		if err := w.currentFile.Sync(); err != nil {
			return fmt.Errorf("failed to sync audit log file: %w", err)
		}
	}

	return nil
}

// writeEntry writes a single entry to the current file
func (w *Writer) writeEntry(log *AuditLog) error {
	// Check if rotation is needed
	if w.currentSize >= w.maxFileSize {
		if err := w.rotateFile(); err != nil {
			return err
		}
	}

	// Record offset before writing
	offset := w.currentSize

	// Encode entry
	data, err := msgpack.Marshal(log)
	if err != nil {
		return fmt.Errorf("failed to encode audit log: %w", err)
	}

	// Write length prefix (4 bytes)
	length := int32(len(data))
	lengthBytes := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}

	if _, err := w.currentFile.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}

	// Write data
	if _, err := w.currentFile.Write(data); err != nil {
		return fmt.Errorf("failed to write audit log data: %w", err)
	}

	// Update size
	w.currentSize += int64(4 + len(data))

	// Add to index
	indexEntry := &IndexEntry{
		ID:        log.ID,
		TenantID:  log.TenantID,
		EventType: log.EventType,
		ActorID:   log.ActorID,
		TargetID:  log.TargetID,
		CreatedAt: log.CreatedAt,
		Offset:    offset,
		Length:    length,
	}

	if err := w.indexer.AddEntry(w.currentFile.Name(), indexEntry); err != nil {
		return fmt.Errorf("failed to add index entry: %w", err)
	}

	return nil
}

// rotateFile creates a new audit log file
func (w *Writer) rotateFile() error {
	// Close current file
	if w.currentFile != nil {
		if err := w.currentFile.Close(); err != nil {
			return fmt.Errorf("failed to close current file: %w", err)
		}
	}

	// Create new file with timestamp
	timestamp := time.Now().UTC().Format("2006-01-02T15-04-05")
	filename := filepath.Join(w.basePath, fmt.Sprintf("audit-%s.log", timestamp))

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create audit log file: %w", err)
	}

	w.currentFile = file
	w.currentSize = 0

	return nil
}

// flushLoop periodically flushes the buffer
func (w *Writer) flushLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := w.Flush(); err != nil {
				// Log error but continue
				fmt.Printf("error flushing audit logs: %v\n", err)
			}
		case <-w.stopCh:
			// Final flush before shutdown
			if err := w.Flush(); err != nil {
				fmt.Printf("error during final flush: %v\n", err)
			}
			return
		}
	}
}

// Close gracefully shuts down the writer
func (w *Writer) Close() error {
	close(w.stopCh)
	w.wg.Wait()

	if w.currentFile != nil {
		if err := w.currentFile.Close(); err != nil {
			return err
		}
	}

	return w.indexer.Close()
}

// Stats returns statistics about the writer
func (w *Writer) Stats() WriterStats {
	w.bufferMu.Lock()
	defer w.bufferMu.Unlock()

	return WriterStats{
		BufferedEntries: len(w.buffer),
		CurrentFileSize: w.currentSize,
	}
}

// WriterStats holds statistics about the writer
type WriterStats struct {
	BufferedEntries int
	CurrentFileSize int64
}
