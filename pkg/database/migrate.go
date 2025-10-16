package database

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/victoralfred/kube_manager/pkg/logger"
)

// Migration represents a database migration
type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
}

// MigrationRunner manages database migrations
type MigrationRunner struct {
	db  *DB
	log *logger.Logger
}

// NewMigrationRunner creates a new migration runner
func NewMigrationRunner(db *DB, log *logger.Logger) *MigrationRunner {
	return &MigrationRunner{
		db:  db,
		log: log,
	}
}

// RunMigrations executes all pending migrations
func (m *MigrationRunner) RunMigrations(migrations embed.FS, migrationDir string) error {
	m.log.Info("starting database migration check")

	// Ensure migration tracking table exists
	if err := m.ensureMigrationTable(); err != nil {
		return fmt.Errorf("failed to create migration table: %w", err)
	}

	// Load all migrations from embedded filesystem
	allMigrations, err := m.loadMigrations(migrations, migrationDir)
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	if len(allMigrations) == 0 {
		m.log.Info("no migrations found")
		return nil
	}

	// Get current migration version
	currentVersion, err := m.getCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current migration version: %w", err)
	}

	m.log.WithField("current_version", currentVersion).Info("current database version")

	// Filter migrations that need to be applied
	pendingMigrations := m.filterPendingMigrations(allMigrations, currentVersion)

	if len(pendingMigrations) == 0 {
		m.log.Info("database is up to date, no migrations to run")
		return nil
	}

	m.log.WithField("count", len(pendingMigrations)).Info("pending migrations found")

	// Apply each migration in order
	for _, migration := range pendingMigrations {
		if err := m.applyMigration(migration); err != nil {
			return fmt.Errorf("failed to apply migration %d_%s: %w", migration.Version, migration.Name, err)
		}
	}

	m.log.Info("all migrations applied successfully")
	return nil
}

// ensureMigrationTable creates the schema_migrations table if it doesn't exist
func (m *MigrationRunner) ensureMigrationTable() error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)
	`

	if _, err := m.db.Exec(query); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	return nil
}

// getCurrentVersion returns the current migration version
func (m *MigrationRunner) getCurrentVersion() (int, error) {
	var version sql.NullInt64

	query := `SELECT MAX(version) FROM schema_migrations`
	err := m.db.QueryRow(query).Scan(&version)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	if !version.Valid {
		return 0, nil
	}

	return int(version.Int64), nil
}

// loadMigrations loads all migration files from embedded filesystem
func (m *MigrationRunner) loadMigrations(migrations embed.FS, migrationDir string) ([]Migration, error) {
	entries, err := migrations.ReadDir(migrationDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read migration directory: %w", err)
	}

	migrationMap := make(map[int]*Migration)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()

		// Parse migration filename: 001_name.up.sql or 001_name.down.sql
		version, name, direction, err := parseMigrationFilename(filename)
		if err != nil {
			m.log.WithField("filename", filename).Warn("skipping invalid migration file")
			continue
		}

		// Read file content
		content, err := migrations.ReadFile(migrationDir + "/" + filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", filename, err)
		}

		// Get or create migration entry
		if migrationMap[version] == nil {
			migrationMap[version] = &Migration{
				Version: version,
				Name:    name,
			}
		}

		// Set content based on direction
		if direction == "up" {
			migrationMap[version].Up = string(content)
		} else {
			migrationMap[version].Down = string(content)
		}
	}

	// Convert map to sorted slice
	versions := make([]int, 0, len(migrationMap))
	for version := range migrationMap {
		versions = append(versions, version)
	}
	sort.Ints(versions)

	result := make([]Migration, 0, len(versions))
	for _, version := range versions {
		migration := migrationMap[version]
		if migration.Up == "" {
			m.log.WithField("version", version).Warn("migration missing up file, skipping")
			continue
		}
		result = append(result, *migration)
	}

	return result, nil
}

// parseMigrationFilename parses a migration filename into version, name, and direction
func parseMigrationFilename(filename string) (version int, name string, direction string, err error) {
	// Expected format: 001_migration_name.up.sql or 001_migration_name.down.sql
	if !strings.HasSuffix(filename, ".sql") {
		return 0, "", "", fmt.Errorf("not a SQL file")
	}

	// Remove .sql extension
	filename = strings.TrimSuffix(filename, ".sql")

	// Check for .up or .down
	if strings.HasSuffix(filename, ".up") {
		direction = "up"
		filename = strings.TrimSuffix(filename, ".up")
	} else if strings.HasSuffix(filename, ".down") {
		direction = "down"
		filename = strings.TrimSuffix(filename, ".down")
	} else {
		return 0, "", "", fmt.Errorf("missing .up or .down in filename")
	}

	// Split by underscore to get version and name
	parts := strings.SplitN(filename, "_", 2)
	if len(parts) != 2 {
		return 0, "", "", fmt.Errorf("invalid filename format")
	}

	// Parse version
	_, err = fmt.Sscanf(parts[0], "%d", &version)
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid version number: %w", err)
	}

	name = parts[1]
	return version, name, direction, nil
}

// filterPendingMigrations returns migrations that haven't been applied yet
func (m *MigrationRunner) filterPendingMigrations(allMigrations []Migration, currentVersion int) []Migration {
	pending := make([]Migration, 0)
	for _, migration := range allMigrations {
		if migration.Version > currentVersion {
			pending = append(pending, migration)
		}
	}
	return pending
}

// applyMigration applies a single migration within a transaction
func (m *MigrationRunner) applyMigration(migration Migration) error {
	m.log.WithField("version", migration.Version).
		WithField("name", migration.Name).
		Info("applying migration")

	// Begin transaction
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute migration SQL
	if _, err := tx.Exec(migration.Up); err != nil {
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	// Record migration in schema_migrations table
	query := `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`
	if _, err := tx.Exec(query, migration.Version, migration.Name); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	m.log.WithField("version", migration.Version).
		WithField("name", migration.Name).
		Info("migration applied successfully")

	return nil
}

// GetAppliedMigrations returns list of applied migrations
func (m *MigrationRunner) GetAppliedMigrations() ([]Migration, error) {
	query := `
		SELECT version, name, applied_at
		FROM schema_migrations
		ORDER BY version ASC
	`

	rows, err := m.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	migrations := make([]Migration, 0)
	for rows.Next() {
		var migration Migration
		var appliedAt string
		if err := rows.Scan(&migration.Version, &migration.Name, &appliedAt); err != nil {
			return nil, err
		}
		migrations = append(migrations, migration)
	}

	return migrations, rows.Err()
}
