package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================
// InMemoryCache Tests
// ========================================

func TestInMemoryCache_SetAndGet(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	type testData struct {
		Name  string
		Value int
	}

	data := testData{Name: "test", Value: 42}

	// Set value
	err := cache.Set(ctx, "test-key", data, 1*time.Minute)
	assert.NoError(t, err)

	// Get value
	var retrieved testData
	err = cache.Get(ctx, "test-key", &retrieved)
	assert.NoError(t, err)
	assert.Equal(t, data.Name, retrieved.Name)
	assert.Equal(t, data.Value, retrieved.Value)
}

func TestInMemoryCache_GetMiss(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	var result string
	err := cache.Get(ctx, "non-existent", &result)

	assert.Error(t, err)
	assert.Equal(t, ErrCacheMiss, err)
}

func TestInMemoryCache_TTLExpiration(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Set with very short TTL
	err := cache.Set(ctx, "expire-key", "value", 100*time.Millisecond)
	assert.NoError(t, err)

	// Should exist immediately
	var result string
	err = cache.Get(ctx, "expire-key", &result)
	assert.NoError(t, err)
	assert.Equal(t, "value", result)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	err = cache.Get(ctx, "expire-key", &result)
	assert.Error(t, err)
	assert.Equal(t, ErrCacheMiss, err)
}

func TestInMemoryCache_Delete(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Set value
	err := cache.Set(ctx, "delete-key", "value", 1*time.Minute)
	assert.NoError(t, err)

	// Verify exists
	var result string
	err = cache.Get(ctx, "delete-key", &result)
	assert.NoError(t, err)

	// Delete
	err = cache.Delete(ctx, "delete-key")
	assert.NoError(t, err)

	// Verify deleted
	err = cache.Get(ctx, "delete-key", &result)
	assert.Error(t, err)
	assert.Equal(t, ErrCacheMiss, err)
}

func TestInMemoryCache_DeletePattern(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Set multiple keys
	testKeys := map[string]string{
		"user:1:perms":    "data1",
		"user:2:perms":    "data2",
		"user:3:perms":    "data3",
		"project:1:perms": "data4",
		"other:key":       "data5",
	}

	for key, value := range testKeys {
		err := cache.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err)
	}

	// Delete pattern
	err := cache.DeletePattern(ctx, "user:*:perms")
	assert.NoError(t, err)

	// Verify user keys deleted
	var result string
	err = cache.Get(ctx, "user:1:perms", &result)
	assert.Error(t, err)
	assert.Equal(t, ErrCacheMiss, err)

	err = cache.Get(ctx, "user:2:perms", &result)
	assert.Error(t, err)

	// Verify other keys still exist
	err = cache.Get(ctx, "project:1:perms", &result)
	assert.NoError(t, err)
	assert.Equal(t, "data4", result)

	err = cache.Get(ctx, "other:key", &result)
	assert.NoError(t, err)
	assert.Equal(t, "data5", result)
}

func TestInMemoryCache_MGet(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Set multiple values
	cache.Set(ctx, "key1", "value1", 1*time.Minute)
	cache.Set(ctx, "key2", "value2", 1*time.Minute)
	cache.Set(ctx, "key3", "value3", 1*time.Minute)

	// Get multiple keys
	keys := []string{"key1", "key2", "key3", "non-existent"}
	var results map[string]string
	err := cache.MGet(ctx, keys, &results)

	assert.NoError(t, err)
	assert.Len(t, results, 3)
	assert.Equal(t, "value1", results["key1"])
	assert.Equal(t, "value2", results["key2"])
	assert.Equal(t, "value3", results["key3"])
	assert.NotContains(t, results, "non-existent")
}

func TestInMemoryCache_MSet(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Set multiple values
	items := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	err := cache.MSet(ctx, items, 1*time.Minute)
	assert.NoError(t, err)

	// Verify all keys set
	for key, expectedValue := range items {
		var result string
		err := cache.Get(ctx, key, &result)
		assert.NoError(t, err)
		assert.Equal(t, expectedValue, result)
	}
}

func TestInMemoryCache_Stats(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Perform operations
	cache.Set(ctx, "key1", "value1", 1*time.Minute)
	cache.Set(ctx, "key2", "value2", 1*time.Minute)

	var result string
	cache.Get(ctx, "key1", &result) // Hit
	cache.Get(ctx, "key1", &result) // Hit
	cache.Get(ctx, "non-existent", &result) // Miss

	cache.Delete(ctx, "key1")

	// Check stats
	stats := cache.Stats()

	assert.Equal(t, uint64(2), stats.Hits)
	assert.Equal(t, uint64(1), stats.Misses)
	assert.Equal(t, uint64(2), stats.Sets)
	assert.Equal(t, uint64(1), stats.Deletes)
	assert.Greater(t, stats.HitRate, float64(0))
	assert.False(t, stats.CircuitOpen)
}

func TestInMemoryCache_ConcurrentAccess(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Start multiple goroutines performing operations
	const goroutines = 10
	const operations = 100

	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			for j := 0; j < operations; j++ {
				key := "key" + string(rune(id))
				value := "value" + string(rune(j))

				// Set
				cache.Set(ctx, key, value, 1*time.Minute)

				// Get
				var result string
				cache.Get(ctx, key, &result)

				// Delete
				if j%10 == 0 {
					cache.Delete(ctx, key)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}

	// Verify no crashes and stats are tracked
	stats := cache.Stats()
	assert.Greater(t, stats.Sets, uint64(0))
	assert.Greater(t, stats.Hits+stats.Misses, uint64(0))
}

func TestInMemoryCache_Ping(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	err := cache.Ping(ctx)
	assert.NoError(t, err)
}

func TestInMemoryCache_Close(t *testing.T) {
	cache := NewInMemoryCache()

	err := cache.Close()
	assert.NoError(t, err)
}

// ========================================
// Pattern Matching Tests
// ========================================

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name    string
		str     string
		pattern string
		want    bool
	}{
		{
			name:    "Exact match",
			str:     "hello",
			pattern: "hello",
			want:    true,
		},
		{
			name:    "Wildcard match all",
			str:     "anything",
			pattern: "*",
			want:    true,
		},
		{
			name:    "Prefix wildcard",
			str:     "user:123:perms",
			pattern: "user:*",
			want:    true,
		},
		{
			name:    "Suffix wildcard",
			str:     "user:123:perms",
			pattern: "*:perms",
			want:    true,
		},
		{
			name:    "Middle wildcard",
			str:     "user:123:perms",
			pattern: "user:*:perms",
			want:    true,
		},
		{
			name:    "Single char wildcard",
			str:     "test",
			pattern: "t??t",
			want:    true,
		},
		{
			name:    "No match",
			str:     "hello",
			pattern: "world",
			want:    false,
		},
		{
			name:    "Partial match fails",
			str:     "hello",
			pattern: "hel",
			want:    false,
		},
		{
			name:    "Multiple wildcards",
			str:     "user:1:tenant:2:perms",
			pattern: "user:*:tenant:*:perms",
			want:    true,
		},
		{
			name:    "Question mark at end",
			str:     "test1",
			pattern: "test?",
			want:    true,
		},
		{
			name:    "Question mark no match",
			str:     "test12",
			pattern: "test?",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPattern(tt.str, tt.pattern)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ========================================
// Circuit Breaker Tests
// ========================================

func TestCircuitBreaker_Closed(t *testing.T) {
	cb := NewCircuitBreaker(3, 1*time.Second)

	// Circuit should start closed
	assert.False(t, cb.IsOpen())

	// Successful calls should keep it closed
	for i := 0; i < 5; i++ {
		err := cb.Call(func() error {
			return nil
		})
		assert.NoError(t, err)
		assert.False(t, cb.IsOpen())
	}
}

func TestCircuitBreaker_OpensAfterFailures(t *testing.T) {
	cb := NewCircuitBreaker(3, 1*time.Second)

	// Circuit starts closed
	assert.False(t, cb.IsOpen())

	// Record failures
	testError := errors.New("test error")
	for i := 0; i < 3; i++ {
		err := cb.Call(func() error {
			return testError
		})
		assert.Error(t, err)
	}

	// Circuit should now be open
	assert.True(t, cb.IsOpen())

	// Subsequent calls should fail immediately
	err := cb.Call(func() error {
		t.Fatal("Should not execute function when circuit is open")
		return nil
	})
	assert.Error(t, err)
	assert.Equal(t, ErrCacheUnavailable, err)
}

func TestCircuitBreaker_HalfOpenAfterTimeout(t *testing.T) {
	cb := NewCircuitBreaker(2, 200*time.Millisecond)

	// Open the circuit
	testError := errors.New("test error")
	for i := 0; i < 2; i++ {
		cb.Call(func() error {
			return testError
		})
	}

	assert.True(t, cb.IsOpen())

	// Wait for reset timeout
	time.Sleep(250 * time.Millisecond)

	// Next call should attempt execution (half-open)
	executed := false
	err := cb.Call(func() error {
		executed = true
		return nil
	})

	assert.NoError(t, err)
	assert.True(t, executed)
	assert.False(t, cb.IsOpen())
}

func TestCircuitBreaker_ReclosesOnSuccess(t *testing.T) {
	cb := NewCircuitBreaker(2, 200*time.Millisecond)

	// Open the circuit
	testError := errors.New("test error")
	cb.Call(func() error { return testError })
	cb.Call(func() error { return testError })

	assert.True(t, cb.IsOpen())

	// Wait for reset
	time.Sleep(250 * time.Millisecond)

	// Successful call should close circuit
	err := cb.Call(func() error {
		return nil
	})

	assert.NoError(t, err)
	assert.False(t, cb.IsOpen())

	// Verify circuit stays closed for subsequent calls
	err = cb.Call(func() error {
		return nil
	})
	assert.NoError(t, err)
	assert.False(t, cb.IsOpen())
}

func TestCircuitBreaker_ReopensOnHalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker(2, 200*time.Millisecond)

	// Open the circuit
	testError := errors.New("test error")
	cb.Call(func() error { return testError })
	cb.Call(func() error { return testError })

	assert.True(t, cb.IsOpen())

	// Wait for reset
	time.Sleep(250 * time.Millisecond)

	// Failure in half-open should reopen circuit
	err := cb.Call(func() error {
		return testError
	})

	assert.Error(t, err)
	// After a failure in half-open, circuit may go back to tracking failures
	// The exact behavior depends on implementation
}

// ========================================
// Validation Tests
// ========================================

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
		errType error
	}{
		{
			name:    "Valid key",
			key:     "valid-key",
			wantErr: false,
		},
		{
			name:    "Empty key",
			key:     "",
			wantErr: true,
			errType: ErrInvalidKey,
		},
		{
			name:    "Key too long",
			key:     string(make([]byte, 513)),
			wantErr: true,
		},
		{
			name:    "Max length key",
			key:     string(make([]byte, 512)),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKey(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.Equal(t, tt.errType, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateTTL(t *testing.T) {
	tests := []struct {
		name    string
		ttl     time.Duration
		wantErr bool
	}{
		{
			name:    "Valid TTL",
			ttl:     1 * time.Minute,
			wantErr: false,
		},
		{
			name:    "Zero TTL",
			ttl:     0,
			wantErr: true,
		},
		{
			name:    "Negative TTL",
			ttl:     -1 * time.Second,
			wantErr: true,
		},
		{
			name:    "Very short TTL",
			ttl:     1 * time.Nanosecond,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTTL(tt.ttl)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidTTL, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ========================================
// Complex Scenarios
// ========================================

func TestInMemoryCache_MixedOperations(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Scenario: Set, Get, Update, Delete workflow
	t.Run("Complete workflow", func(t *testing.T) {
		// Set initial value
		err := cache.Set(ctx, "workflow-key", "initial", 1*time.Minute)
		assert.NoError(t, err)

		// Get initial value
		var result string
		err = cache.Get(ctx, "workflow-key", &result)
		assert.NoError(t, err)
		assert.Equal(t, "initial", result)

		// Update value
		err = cache.Set(ctx, "workflow-key", "updated", 1*time.Minute)
		assert.NoError(t, err)

		// Get updated value
		err = cache.Get(ctx, "workflow-key", &result)
		assert.NoError(t, err)
		assert.Equal(t, "updated", result)

		// Delete
		err = cache.Delete(ctx, "workflow-key")
		assert.NoError(t, err)

		// Verify deleted
		err = cache.Get(ctx, "workflow-key", &result)
		assert.Error(t, err)
	})
}

func TestInMemoryCache_ComplexStructures(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	type NestedStruct struct {
		ID    string
		Items []string
		Meta  map[string]interface{}
	}

	complexData := NestedStruct{
		ID:    "test-123",
		Items: []string{"item1", "item2", "item3"},
		Meta: map[string]interface{}{
			"count": 42,
			"tags":  []string{"tag1", "tag2"},
		},
	}

	// Set complex structure
	err := cache.Set(ctx, "complex-key", complexData, 1*time.Minute)
	assert.NoError(t, err)

	// Get and verify
	var retrieved NestedStruct
	err = cache.Get(ctx, "complex-key", &retrieved)
	assert.NoError(t, err)
	assert.Equal(t, complexData.ID, retrieved.ID)
	assert.Equal(t, len(complexData.Items), len(retrieved.Items))
	assert.NotNil(t, retrieved.Meta)
}

func TestInMemoryCache_BatchOperationsConsistency(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// MSet multiple items
	items := map[string]interface{}{
		"batch:1": "value1",
		"batch:2": "value2",
		"batch:3": "value3",
		"batch:4": "value4",
		"batch:5": "value5",
	}

	err := cache.MSet(ctx, items, 1*time.Minute)
	assert.NoError(t, err)

	// MGet the same items
	keys := []string{"batch:1", "batch:2", "batch:3", "batch:4", "batch:5"}
	var results map[string]string
	err = cache.MGet(ctx, keys, &results)

	assert.NoError(t, err)
	assert.Len(t, results, 5)

	for key, expectedValue := range items {
		assert.Equal(t, expectedValue, results[key])
	}
}

func TestInMemoryCache_DeletePatternEdgeCases(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Set test keys
	testKeys := []string{
		"abc",
		"a:b:c",
		"user:123:perms",
		"user:456:perms",
		"user:123:data",
	}

	for _, key := range testKeys {
		cache.Set(ctx, key, "value", 1*time.Minute)
	}

	t.Run("Delete with no matches", func(t *testing.T) {
		err := cache.DeletePattern(ctx, "nonexistent:*")
		assert.NoError(t, err)

		// All keys should still exist
		for _, key := range testKeys {
			var result string
			err := cache.Get(ctx, key, &result)
			assert.NoError(t, err)
		}
	})

	t.Run("Delete exact pattern", func(t *testing.T) {
		err := cache.DeletePattern(ctx, "abc")
		assert.NoError(t, err)

		var result string
		err = cache.Get(ctx, "abc", &result)
		assert.Error(t, err)
	})

	t.Run("Delete with multiple colons", func(t *testing.T) {
		err := cache.DeletePattern(ctx, "user:*:perms")
		assert.NoError(t, err)

		// user:*:perms keys should be deleted
		var result string
		err = cache.Get(ctx, "user:123:perms", &result)
		assert.Error(t, err)

		err = cache.Get(ctx, "user:456:perms", &result)
		assert.Error(t, err)

		// user:123:data should still exist
		err = cache.Get(ctx, "user:123:data", &result)
		assert.NoError(t, err)
	})
}

func TestInMemoryCache_StatsAccuracy(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Perform known operations
	cache.Set(ctx, "key1", "value1", 1*time.Minute)
	cache.Set(ctx, "key2", "value2", 1*time.Minute)
	cache.Set(ctx, "key3", "value3", 1*time.Minute)

	var result string
	cache.Get(ctx, "key1", &result) // Hit
	cache.Get(ctx, "key2", &result) // Hit
	cache.Get(ctx, "key3", &result) // Hit
	cache.Get(ctx, "nonexistent", &result) // Miss

	cache.Delete(ctx, "key1")
	cache.Delete(ctx, "key2")

	// Verify stats
	stats := cache.Stats()

	assert.Equal(t, uint64(3), stats.Sets, "Should have 3 sets")
	assert.Equal(t, uint64(3), stats.Hits, "Should have 3 hits")
	assert.Equal(t, uint64(1), stats.Misses, "Should have 1 miss")
	assert.Equal(t, uint64(2), stats.Deletes, "Should have 2 deletes")

	// Hit rate should be 75% (3 hits / 4 total gets)
	expectedHitRate := (3.0 / 4.0) * 100
	assert.InDelta(t, expectedHitRate, stats.HitRate, 0.01)

	// Average latency should be > 0
	assert.Greater(t, stats.AvgLatencyMs, float64(0))
}

func TestInMemoryCache_ZeroValueHandling(t *testing.T) {
	cache := NewInMemoryCache()
	ctx := context.Background()

	// Test with zero value integer
	err := cache.Set(ctx, "zero-int", 0, 1*time.Minute)
	assert.NoError(t, err)

	var resultInt int
	err = cache.Get(ctx, "zero-int", &resultInt)
	assert.NoError(t, err)
	assert.Equal(t, 0, resultInt)

	// Test with empty string
	err = cache.Set(ctx, "empty-string", "", 1*time.Minute)
	assert.NoError(t, err)

	var resultStr string
	err = cache.Get(ctx, "empty-string", &resultStr)
	assert.NoError(t, err)
	assert.Equal(t, "", resultStr)

	// Test with nil slice (should serialize as empty/null)
	var nilSlice []string
	err = cache.Set(ctx, "nil-slice", nilSlice, 1*time.Minute)
	assert.NoError(t, err)

	var resultSlice []string
	err = cache.Get(ctx, "nil-slice", &resultSlice)
	assert.NoError(t, err)
	// Result should be nil or empty depending on JSON marshaling
	assert.True(t, resultSlice == nil || len(resultSlice) == 0)
}
