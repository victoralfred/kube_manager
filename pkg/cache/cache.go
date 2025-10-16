// Package cache provides production-ready caching implementations with circuit breaker,
// atomic metrics tracking, and comprehensive error handling.
//
// Features:
// - Redis cache with circuit breaker pattern for fault tolerance
// - In-memory cache with automatic expiration cleanup
// - Atomic metrics tracking for hits, misses, latency
// - Batch operations (MGet/MSet) for efficiency
// - Pattern-based key deletion
// - Thread-safe concurrent access
//
// Example usage:
//
//	// Redis cache
//	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
//	cache := cache.NewRedisCache(cache.RedisConfig{Client: client})
//	defer cache.Close()
//
//	// In-memory cache (for testing/dev)
//	cache := cache.NewInMemoryCache()
//
//	// Set value
//	cache.Set(ctx, "key", myStruct, 5*time.Minute)
//
//	// Get value
//	var result MyStruct
//	err := cache.Get(ctx, "key", &result)
//
//	// Pattern deletion
//	cache.DeletePattern(ctx, "user:*:perms")
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
)

var (
	ErrCacheMiss        = errors.New("cache miss")
	ErrCacheUnavailable = errors.New("cache unavailable")
	ErrInvalidValue     = errors.New("invalid cache value")
	ErrInvalidKey       = errors.New("invalid cache key: key cannot be empty")
	ErrInvalidTTL       = errors.New("invalid ttl: must be positive")
)

// validateKey checks if cache key is valid
func validateKey(key string) error {
	if key == "" {
		return ErrInvalidKey
	}
	if len(key) > 512 {
		return fmt.Errorf("cache key too long: max 512 characters, got %d", len(key))
	}
	return nil
}

// validateTTL checks if TTL is valid
func validateTTL(ttl time.Duration) error {
	if ttl <= 0 {
		return ErrInvalidTTL
	}
	return nil
}

// Cache defines the interface for caching implementations
type Cache interface {
	// Core operations
	Get(ctx context.Context, key string, dest interface{}) error
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	DeletePattern(ctx context.Context, pattern string) error

	// Batch operations
	MGet(ctx context.Context, keys []string, dest interface{}) error
	MSet(ctx context.Context, items map[string]interface{}, ttl time.Duration) error

	// Health and metrics
	Ping(ctx context.Context) error
	Stats() CacheStats

	// Lifecycle
	Close() error
}

// CacheStats provides cache metrics
type CacheStats struct {
	Hits          uint64
	Misses        uint64
	Sets          uint64
	Deletes       uint64
	Errors        uint64
	HitRate       float64
	AvgLatencyMs  float64
	CircuitOpen   bool
	LastError     error
	LastErrorTime time.Time
}

// RedisCache implements production-ready Redis caching with circuit breaker
type RedisCache struct {
	client          *redis.Client
	fallbackEnabled bool
	circuitBreaker  *CircuitBreaker
	metrics         *cacheMetrics
	mu              sync.RWMutex
}

// cacheMetrics tracks cache performance
type cacheMetrics struct {
	hits          uint64
	misses        uint64
	sets          uint64
	deletes       uint64
	errors        uint64
	totalLatency  uint64 // microseconds
	operations    uint64
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	maxFailures   uint32
	resetTimeout  time.Duration
	failures      uint32
	lastFailTime  time.Time
	state         uint32 // 0=closed, 1=open, 2=half-open
	mu            sync.RWMutex
}

const (
	circuitClosed   = 0
	circuitOpen     = 1
	circuitHalfOpen = 2
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures uint32, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        circuitClosed,
	}
}

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	if !cb.canExecute() {
		return ErrCacheUnavailable
	}

	err := fn()

	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

func (cb *CircuitBreaker) canExecute() bool {
	cb.mu.RLock()
	state := atomic.LoadUint32(&cb.state)
	cb.mu.RUnlock()

	switch state {
	case circuitClosed:
		return true
	case circuitOpen:
		// Check if we should transition to half-open
		cb.mu.RLock()
		elapsed := time.Since(cb.lastFailTime)
		cb.mu.RUnlock()

		if elapsed > cb.resetTimeout {
			atomic.StoreUint32(&cb.state, circuitHalfOpen)
			return true
		}
		return false
	case circuitHalfOpen:
		return true
	default:
		return false
	}
}

func (cb *CircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailTime = time.Now()

	if cb.failures >= cb.maxFailures {
		atomic.StoreUint32(&cb.state, circuitOpen)
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	state := atomic.LoadUint32(&cb.state)

	if state == circuitHalfOpen {
		cb.failures = 0
		atomic.StoreUint32(&cb.state, circuitClosed)
	}
}

func (cb *CircuitBreaker) IsOpen() bool {
	return atomic.LoadUint32(&cb.state) == circuitOpen
}

// RedisConfig holds Redis cache configuration
type RedisConfig struct {
	Client          *redis.Client
	FallbackEnabled bool
	MaxFailures     uint32
	ResetTimeout    time.Duration
}

// NewRedisCache creates a production-ready Redis cache with validation
func NewRedisCache(config RedisConfig) (*RedisCache, error) {
	// Validate required config
	if config.Client == nil {
		return nil, errors.New("redis client is required")
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := config.Client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	// Set defaults
	if config.MaxFailures == 0 {
		config.MaxFailures = 5
	}
	if config.ResetTimeout == 0 {
		config.ResetTimeout = 30 * time.Second
	}

	return &RedisCache{
		client:          config.Client,
		fallbackEnabled: config.FallbackEnabled,
		circuitBreaker:  NewCircuitBreaker(config.MaxFailures, config.ResetTimeout),
		metrics:         &cacheMetrics{},
	}, nil
}

// MustNewRedisCache creates a Redis cache and panics on error (use in main/init only)
func MustNewRedisCache(config RedisConfig) *RedisCache {
	cache, err := NewRedisCache(config)
	if err != nil {
		panic(fmt.Sprintf("failed to create redis cache: %v", err))
	}
	return cache
}

// Get retrieves and unmarshals a value from cache
func (c *RedisCache) Get(ctx context.Context, key string, dest interface{}) error {
	// Validate inputs
	if err := validateKey(key); err != nil {
		return err
	}
	if dest == nil {
		return errors.New("destination cannot be nil")
	}

	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	var val string
	err := c.circuitBreaker.Call(func() error {
		var err error
		val, err = c.client.Get(ctx, key).Result()
		return err
	})

	if err == redis.Nil {
		atomic.AddUint64(&c.metrics.misses, 1)
		return ErrCacheMiss
	}

	if err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		if errors.Is(err, ErrCacheUnavailable) {
			return err
		}
		return fmt.Errorf("cache get failed: %w", err)
	}

	// Unmarshal into destination
	if err := json.Unmarshal([]byte(val), dest); err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("failed to unmarshal cached value: %w", err)
	}

	atomic.AddUint64(&c.metrics.hits, 1)
	return nil
}

// Set marshals and stores a value in cache
func (c *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	// Validate inputs
	if err := validateKey(key); err != nil {
		return err
	}
	if value == nil {
		return errors.New("value cannot be nil")
	}
	if err := validateTTL(ttl); err != nil {
		return err
	}

	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	// Marshal to JSON
	data, err := json.Marshal(value)
	if err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	err = c.circuitBreaker.Call(func() error {
		return c.client.Set(ctx, key, data, ttl).Err()
	})

	if err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("cache set failed: %w", err)
	}

	atomic.AddUint64(&c.metrics.sets, 1)
	return nil
}

// Delete removes a key from cache
func (c *RedisCache) Delete(ctx context.Context, key string) error {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	err := c.circuitBreaker.Call(func() error {
		return c.client.Del(ctx, key).Err()
	})

	if err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("cache delete failed: %w", err)
	}

	atomic.AddUint64(&c.metrics.deletes, 1)
	return nil
}

// DeletePattern deletes all keys matching a pattern
func (c *RedisCache) DeletePattern(ctx context.Context, pattern string) error {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	var cursor uint64
	var keys []string

	err := c.circuitBreaker.Call(func() error {
		// Scan for matching keys
		for {
			var scanKeys []string
			var err error
			scanKeys, cursor, err = c.client.Scan(ctx, cursor, pattern, 100).Result()
			if err != nil {
				return err
			}

			keys = append(keys, scanKeys...)

			if cursor == 0 {
				break
			}
		}

		// Delete all matching keys in batches
		if len(keys) > 0 {
			// Use pipeline for efficiency
			pipe := c.client.Pipeline()
			for _, key := range keys {
				pipe.Del(ctx, key)
			}
			_, err := pipe.Exec(ctx)
			return err
		}

		return nil
	})

	if err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("cache delete pattern failed: %w", err)
	}

	atomic.AddUint64(&c.metrics.deletes, uint64(len(keys)))
	return nil
}

// MGet retrieves multiple keys at once
func (c *RedisCache) MGet(ctx context.Context, keys []string, dest interface{}) error {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	var vals []interface{}
	err := c.circuitBreaker.Call(func() error {
		var err error
		vals, err = c.client.MGet(ctx, keys...).Result()
		return err
	})

	if err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("cache mget failed: %w", err)
	}

	// Process results
	results := make(map[string]interface{})
	for i, val := range vals {
		if val != nil {
			results[keys[i]] = val
			atomic.AddUint64(&c.metrics.hits, 1)
		} else {
			atomic.AddUint64(&c.metrics.misses, 1)
		}
	}

	// Marshal results into destination
	data, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("failed to unmarshal results: %w", err)
	}

	return nil
}

// MSet sets multiple keys at once
func (c *RedisCache) MSet(ctx context.Context, items map[string]interface{}, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	err := c.circuitBreaker.Call(func() error {
		// Use pipeline for efficiency
		pipe := c.client.Pipeline()

		for key, value := range items {
			data, err := json.Marshal(value)
			if err != nil {
				return fmt.Errorf("failed to marshal value for key %s: %w", key, err)
			}
			pipe.Set(ctx, key, data, ttl)
		}

		_, err := pipe.Exec(ctx)
		return err
	})

	if err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("cache mset failed: %w", err)
	}

	atomic.AddUint64(&c.metrics.sets, uint64(len(items)))
	return nil
}

// Ping checks Redis connection
func (c *RedisCache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Stats returns cache statistics
func (c *RedisCache) Stats() CacheStats {
	hits := atomic.LoadUint64(&c.metrics.hits)
	misses := atomic.LoadUint64(&c.metrics.misses)
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	ops := atomic.LoadUint64(&c.metrics.operations)
	totalLatency := atomic.LoadUint64(&c.metrics.totalLatency)
	var avgLatency float64
	if ops > 0 {
		avgLatency = float64(totalLatency) / float64(ops) / 1000 // Convert to ms
	}

	return CacheStats{
		Hits:         hits,
		Misses:       misses,
		Sets:         atomic.LoadUint64(&c.metrics.sets),
		Deletes:      atomic.LoadUint64(&c.metrics.deletes),
		Errors:       atomic.LoadUint64(&c.metrics.errors),
		HitRate:      hitRate,
		AvgLatencyMs: avgLatency,
		CircuitOpen:  c.circuitBreaker.IsOpen(),
	}
}

// Close closes the Redis connection
func (c *RedisCache) Close() error {
	return c.client.Close()
}

// InMemoryCache is a production-ready in-memory cache for testing or development
type InMemoryCache struct {
	data    map[string]cacheItem
	mu      sync.RWMutex
	metrics *cacheMetrics
}

type cacheItem struct {
	value      []byte // Store as bytes for consistency
	expiration time.Time
}

// NewInMemoryCache creates a new in-memory cache
func NewInMemoryCache() *InMemoryCache {
	cache := &InMemoryCache{
		data:    make(map[string]cacheItem),
		metrics: &cacheMetrics{},
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// cleanup removes expired items periodically
func (c *InMemoryCache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, item := range c.data {
			if now.After(item.expiration) {
				delete(c.data, key)
			}
		}
		c.mu.Unlock()
	}
}

// Get retrieves a value from in-memory cache
func (c *InMemoryCache) Get(ctx context.Context, key string, dest interface{}) error {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	c.mu.RLock()
	item, exists := c.data[key]
	c.mu.RUnlock()

	if !exists {
		atomic.AddUint64(&c.metrics.misses, 1)
		return ErrCacheMiss
	}

	// Check expiration
	if time.Now().After(item.expiration) {
		c.mu.Lock()
		delete(c.data, key)
		c.mu.Unlock()
		atomic.AddUint64(&c.metrics.misses, 1)
		return ErrCacheMiss
	}

	// Unmarshal
	if err := json.Unmarshal(item.value, dest); err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("failed to unmarshal cached value: %w", err)
	}

	atomic.AddUint64(&c.metrics.hits, 1)
	return nil
}

// Set stores a value in in-memory cache
func (c *InMemoryCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	data, err := json.Marshal(value)
	if err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	c.mu.Lock()
	c.data[key] = cacheItem{
		value:      data,
		expiration: time.Now().Add(ttl),
	}
	c.mu.Unlock()

	atomic.AddUint64(&c.metrics.sets, 1)
	return nil
}

// Delete removes a value from in-memory cache
func (c *InMemoryCache) Delete(ctx context.Context, key string) error {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	c.mu.Lock()
	delete(c.data, key)
	c.mu.Unlock()

	atomic.AddUint64(&c.metrics.deletes, 1)
	return nil
}

// DeletePattern deletes all keys matching a pattern
func (c *InMemoryCache) DeletePattern(ctx context.Context, pattern string) error {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple wildcard matching
	var deleted uint64
	for key := range c.data {
		if matchPattern(key, pattern) {
			delete(c.data, key)
			deleted++
		}
	}

	atomic.AddUint64(&c.metrics.deletes, deleted)
	return nil
}

// MGet retrieves multiple keys from in-memory cache
func (c *InMemoryCache) MGet(ctx context.Context, keys []string, dest interface{}) error {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	results := make(map[string]interface{})

	for _, key := range keys {
		item, exists := c.data[key]
		if !exists {
			atomic.AddUint64(&c.metrics.misses, 1)
			continue
		}

		// Check expiration
		if now.After(item.expiration) {
			atomic.AddUint64(&c.metrics.misses, 1)
			continue
		}

		// Unmarshal into temporary variable
		var value interface{}
		if err := json.Unmarshal(item.value, &value); err != nil {
			atomic.AddUint64(&c.metrics.errors, 1)
			continue
		}

		results[key] = value
		atomic.AddUint64(&c.metrics.hits, 1)
	}

	// Marshal results into destination
	data, err := json.Marshal(results)
	if err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		atomic.AddUint64(&c.metrics.errors, 1)
		return fmt.Errorf("failed to unmarshal results: %w", err)
	}

	return nil
}

// MSet sets multiple keys in in-memory cache (batched for efficiency)
func (c *InMemoryCache) MSet(ctx context.Context, items map[string]interface{}, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&c.metrics.operations, 1)
		atomic.AddUint64(&c.metrics.totalLatency, uint64(time.Since(start).Microseconds()))
	}()

	if len(items) == 0 {
		return nil
	}

	// Pre-marshal all values before acquiring lock (minimize lock time)
	marshaled := make(map[string][]byte, len(items))
	for key, value := range items {
		data, err := json.Marshal(value)
		if err != nil {
			atomic.AddUint64(&c.metrics.errors, 1)
			return fmt.Errorf("failed to marshal value for key %s: %w", key, err)
		}
		marshaled[key] = data
	}

	// Batch insert with single lock
	expiration := time.Now().Add(ttl)
	c.mu.Lock()
	for key, data := range marshaled {
		c.data[key] = cacheItem{
			value:      data,
			expiration: expiration,
		}
	}
	c.mu.Unlock()

	atomic.AddUint64(&c.metrics.sets, uint64(len(items)))
	return nil
}

// Ping always returns nil for in-memory cache
func (c *InMemoryCache) Ping(ctx context.Context) error {
	return nil
}

// Stats returns cache statistics
func (c *InMemoryCache) Stats() CacheStats {
	hits := atomic.LoadUint64(&c.metrics.hits)
	misses := atomic.LoadUint64(&c.metrics.misses)
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	ops := atomic.LoadUint64(&c.metrics.operations)
	totalLatency := atomic.LoadUint64(&c.metrics.totalLatency)
	var avgLatency float64
	if ops > 0 {
		avgLatency = float64(totalLatency) / float64(ops) / 1000
	}

	return CacheStats{
		Hits:         hits,
		Misses:       misses,
		Sets:         atomic.LoadUint64(&c.metrics.sets),
		Deletes:      atomic.LoadUint64(&c.metrics.deletes),
		Errors:       atomic.LoadUint64(&c.metrics.errors),
		HitRate:      hitRate,
		AvgLatencyMs: avgLatency,
		CircuitOpen:  false,
	}
}

// Close is a no-op for in-memory cache
func (c *InMemoryCache) Close() error {
	return nil
}

// matchPattern performs glob-style pattern matching (production-ready)
// Supports: * (wildcard), ? (single char), and literal matching
func matchPattern(str, pattern string) bool {
	// Fast path: exact match
	if str == pattern {
		return true
	}

	// Fast path: match all
	if pattern == "*" {
		return true
	}

	return globMatch(str, pattern)
}

// globMatch implements recursive glob matching
func globMatch(str, pattern string) bool {
	sLen, pLen := len(str), len(pattern)
	si, pi := 0, 0
	starIdx, matchIdx := -1, 0

	for si < sLen {
		// Match single character or literal
		if pi < pLen && (pattern[pi] == '?' || pattern[pi] == str[si]) {
			si++
			pi++
		} else if pi < pLen && pattern[pi] == '*' {
			// Wildcard - record position
			starIdx = pi
			matchIdx = si
			pi++
		} else if starIdx != -1 {
			// Backtrack to last wildcard
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			// No match and no wildcard to backtrack
			return false
		}
	}

	// Check remaining pattern chars (must all be '*')
	for pi < pLen {
		if pattern[pi] != '*' {
			return false
		}
		pi++
	}

	return true
}
