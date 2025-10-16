package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Indexer maintains indexes for fast audit log lookups
type Indexer struct {
	basePath string
	mu       sync.RWMutex

	// Indexes by various fields
	byID        map[string]*IndexEntry
	byTenantID  map[string][]*IndexEntry
	byActorID   map[string][]*IndexEntry
	byEventType map[string][]*IndexEntry
	byDate      map[string][]*IndexEntry // Date in YYYY-MM-DD format

	indexFile *os.File
}

// NewIndexer creates a new indexer
func NewIndexer(basePath string) (*Indexer, error) {
	indexPath := filepath.Join(basePath, "audit.index")

	idx := &Indexer{
		basePath:    basePath,
		byID:        make(map[string]*IndexEntry),
		byTenantID:  make(map[string][]*IndexEntry),
		byActorID:   make(map[string][]*IndexEntry),
		byEventType: make(map[string][]*IndexEntry),
		byDate:      make(map[string][]*IndexEntry),
	}

	// Try to load existing index
	if _, err := os.Stat(indexPath); err == nil {
		if err := idx.loadIndex(indexPath); err != nil {
			return nil, fmt.Errorf("failed to load index: %w", err)
		}
	}

	// Open index file for appending
	file, err := os.OpenFile(indexPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open index file: %w", err)
	}
	idx.indexFile = file

	return idx, nil
}

// AddEntry adds an entry to the index
func (i *Indexer) AddEntry(filename string, entry *IndexEntry) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Add to ID index
	i.byID[entry.ID] = entry

	// Add to tenant index
	if entry.TenantID != nil {
		i.byTenantID[*entry.TenantID] = append(i.byTenantID[*entry.TenantID], entry)
	}

	// Add to actor index
	if entry.ActorID != "" {
		i.byActorID[entry.ActorID] = append(i.byActorID[entry.ActorID], entry)
	}

	// Add to event type index
	if entry.EventType != "" {
		i.byEventType[entry.EventType] = append(i.byEventType[entry.EventType], entry)
	}

	// Add to date index
	dateKey := entry.CreatedAt.Format("2006-01-02")
	i.byDate[dateKey] = append(i.byDate[dateKey], entry)

	// Persist to index file
	return i.persistEntry(filename, entry)
}

// persistEntry writes an index entry to the index file
func (i *Indexer) persistEntry(filename string, entry *IndexEntry) error {
	record := struct {
		Filename  string       `json:"filename"`
		Entry     *IndexEntry  `json:"entry"`
		Timestamp time.Time    `json:"timestamp"`
	}{
		Filename:  filepath.Base(filename),
		Entry:     entry,
		Timestamp: time.Now().UTC(),
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal index entry: %w", err)
	}

	data = append(data, '\n')
	if _, err := i.indexFile.Write(data); err != nil {
		return fmt.Errorf("failed to write index entry: %w", err)
	}

	return nil
}

// loadIndex loads the index from disk
func (i *Indexer) loadIndex(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	for decoder.More() {
		var record struct {
			Filename  string       `json:"filename"`
			Entry     *IndexEntry  `json:"entry"`
			Timestamp time.Time    `json:"timestamp"`
		}

		if err := decoder.Decode(&record); err != nil {
			continue // Skip malformed entries
		}

		entry := record.Entry

		// Add to indexes
		i.byID[entry.ID] = entry

		if entry.TenantID != nil {
			i.byTenantID[*entry.TenantID] = append(i.byTenantID[*entry.TenantID], entry)
		}

		if entry.ActorID != "" {
			i.byActorID[entry.ActorID] = append(i.byActorID[entry.ActorID], entry)
		}

		if entry.EventType != "" {
			i.byEventType[entry.EventType] = append(i.byEventType[entry.EventType], entry)
		}

		dateKey := entry.CreatedAt.Format("2006-01-02")
		i.byDate[dateKey] = append(i.byDate[dateKey], entry)
	}

	return nil
}

// Query performs a query against the index
func (i *Indexer) Query(filter QueryFilter) []*IndexEntry {
	i.mu.RLock()
	defer i.mu.RUnlock()

	var candidates []*IndexEntry

	// Start with the most selective index
	if filter.TenantID != nil {
		candidates = i.byTenantID[*filter.TenantID]
	} else if filter.ActorID != "" {
		candidates = i.byActorID[filter.ActorID]
	} else if filter.EventType != "" {
		candidates = i.byEventType[filter.EventType]
	} else {
		// No selective index, scan all entries
		candidates = make([]*IndexEntry, 0, len(i.byID))
		for _, entry := range i.byID {
			candidates = append(candidates, entry)
		}
	}

	// Apply additional filters
	results := make([]*IndexEntry, 0)
	for _, entry := range candidates {
		if i.matchesFilter(entry, filter) {
			results = append(results, entry)
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})

	// Apply pagination
	if filter.Offset > 0 {
		if filter.Offset >= len(results) {
			return []*IndexEntry{}
		}
		results = results[filter.Offset:]
	}

	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	return results
}

// matchesFilter checks if an entry matches the query filter
func (i *Indexer) matchesFilter(entry *IndexEntry, filter QueryFilter) bool {
	// Tenant ID filter
	if filter.TenantID != nil {
		if entry.TenantID == nil || *entry.TenantID != *filter.TenantID {
			return false
		}
	}

	// Actor ID filter
	if filter.ActorID != "" && entry.ActorID != filter.ActorID {
		return false
	}

	// Event type filter
	if filter.EventType != "" && entry.EventType != filter.EventType {
		return false
	}

	// Target ID filter
	if filter.TargetID != "" && entry.TargetID != filter.TargetID {
		return false
	}

	// Time range filter
	if !filter.StartTime.IsZero() && entry.CreatedAt.Before(filter.StartTime) {
		return false
	}

	if !filter.EndTime.IsZero() && entry.CreatedAt.After(filter.EndTime) {
		return false
	}

	return true
}

// GetByID retrieves an index entry by ID
func (i *Indexer) GetByID(id string) *IndexEntry {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return i.byID[id]
}

// Close closes the indexer
func (i *Indexer) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.indexFile != nil {
		return i.indexFile.Close()
	}

	return nil
}

// Stats returns statistics about the index
func (i *Indexer) Stats() IndexerStats {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return IndexerStats{
		TotalEntries:   len(i.byID),
		TenantCount:    len(i.byTenantID),
		ActorCount:     len(i.byActorID),
		EventTypeCount: len(i.byEventType),
		DateCount:      len(i.byDate),
	}
}

// IndexerStats holds statistics about the indexer
type IndexerStats struct {
	TotalEntries   int
	TenantCount    int
	ActorCount     int
	EventTypeCount int
	DateCount      int
}
