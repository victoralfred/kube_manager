package audit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/vmihailenco/msgpack/v5"
)

// Reader reads audit logs using the index for efficient queries
type Reader struct {
	basePath string
	indexer  *Indexer

	// Cache of open file handles
	fileCache   map[string]*os.File
	fileCacheMu sync.RWMutex
}

// NewReader creates a new audit log reader
func NewReader(basePath string) (*Reader, error) {
	indexer, err := NewIndexer(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create indexer: %w", err)
	}

	return &Reader{
		basePath:  basePath,
		indexer:   indexer,
		fileCache: make(map[string]*os.File),
	}, nil
}

// Query retrieves audit logs matching the filter
func (r *Reader) Query(filter QueryFilter) ([]*AuditLog, error) {
	// Get index entries matching the filter
	indexEntries := r.indexer.Query(filter)

	// Read the actual log entries
	logs := make([]*AuditLog, 0, len(indexEntries))
	for _, entry := range indexEntries {
		log, err := r.readEntry(entry)
		if err != nil {
			// Log error but continue with other entries
			continue
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// GetByID retrieves a single audit log by ID
func (r *Reader) GetByID(id string) (*AuditLog, error) {
	indexEntry := r.indexer.GetByID(id)
	if indexEntry == nil {
		return nil, fmt.Errorf("audit log not found: %s", id)
	}

	return r.readEntry(indexEntry)
}

// readEntry reads a single entry from disk using the index
func (r *Reader) readEntry(entry *IndexEntry) (*AuditLog, error) {
	// Get filename from index entry
	filename := r.getFilename(entry)

	// Get file handle (cached)
	file, err := r.getFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	// Seek to offset
	if _, err := file.Seek(entry.Offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to offset: %w", err)
	}

	// Read length prefix
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(file, lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read length prefix: %w", err)
	}

	// Parse length
	length := int32(lengthBytes[0])<<24 | int32(lengthBytes[1])<<16 |
		int32(lengthBytes[2])<<8 | int32(lengthBytes[3])

	// Verify length matches index
	if length != entry.Length {
		return nil, fmt.Errorf("length mismatch: expected %d, got %d", entry.Length, length)
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Decode
	var log AuditLog
	if err := msgpack.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("failed to decode audit log: %w", err)
	}

	return &log, nil
}

// getFilename constructs the filename from an index entry
func (r *Reader) getFilename(entry *IndexEntry) string {
	// For now, assume the filename is stored in a way we can reconstruct
	// In a production system, you'd store the filename in the index entry
	// For this implementation, we'll search for files that contain this offset
	files, _ := filepath.Glob(filepath.Join(r.basePath, "audit-*.log"))

	// Try to find the file that contains this entry
	for _, file := range files {
		stat, err := os.Stat(file)
		if err != nil {
			continue
		}

		// If the offset is within this file's size, it's likely the right file
		// This is a simplified approach - in production you'd track filename in index
		if entry.Offset < stat.Size() {
			return file
		}
	}

	// Fallback to the most recent file
	if len(files) > 0 {
		return files[len(files)-1]
	}

	return filepath.Join(r.basePath, "audit.log")
}

// getFile retrieves a cached file handle or opens a new one
func (r *Reader) getFile(filename string) (*os.File, error) {
	r.fileCacheMu.RLock()
	file, exists := r.fileCache[filename]
	r.fileCacheMu.RUnlock()

	if exists {
		return file, nil
	}

	// Open new file
	r.fileCacheMu.Lock()
	defer r.fileCacheMu.Unlock()

	// Double-check after acquiring write lock
	if file, exists := r.fileCache[filename]; exists {
		return file, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	r.fileCache[filename] = file
	return file, nil
}

// Close closes the reader and all cached file handles
func (r *Reader) Close() error {
	r.fileCacheMu.Lock()
	defer r.fileCacheMu.Unlock()

	for _, file := range r.fileCache {
		if err := file.Close(); err != nil {
			return err
		}
	}

	r.fileCache = make(map[string]*os.File)

	return r.indexer.Close()
}

// Stats returns statistics about the reader
func (r *Reader) Stats() ReaderStats {
	r.fileCacheMu.RLock()
	defer r.fileCacheMu.RUnlock()

	return ReaderStats{
		CachedFiles:  len(r.fileCache),
		IndexerStats: r.indexer.Stats(),
	}
}

// ReaderStats holds statistics about the reader
type ReaderStats struct {
	CachedFiles  int
	IndexerStats IndexerStats
}
