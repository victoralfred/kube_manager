# Database Migrations

This directory contains all database migration files for the kube_manager application.

## Automatic Migrations

**Migrations are automatically run at application startup.** When the server starts, it:
1. Checks for pending migrations
2. Applies them in order
3. Records which migrations have been applied in the `schema_migrations` table

This ensures your database schema is always up-to-date without manual intervention.

## Migration Files

Migrations are stored in the `files/` subdirectory and are embedded into the binary at build time.

### File Naming Convention

Migration files follow this naming pattern:
```
<version>_<name>.<direction>.sql
```

Examples:
- `001_init_schema.up.sql`
- `001_init_schema.down.sql`
- `002_create_users.up.sql`
- `002_create_users.down.sql`

Where:
- **version**: Three-digit sequential number (001, 002, 003, etc.)
- **name**: Descriptive name using underscores
- **direction**: Either `up` (apply) or `down` (rollback)

## Creating New Migrations

Use the Makefile command to create a new migration:

```bash
make migrate-create NAME=add_email_templates
```

This will create two files:
- `009_add_email_templates.up.sql` - Contains SQL to apply the migration
- `009_add_email_templates.down.sql` - Contains SQL to rollback the migration

The version number is automatically incremented.

## Migration Structure

### Up Migration (Required)
Contains SQL statements to apply the schema change:

```sql
-- Migration: add_email_templates
-- Created: 2025-10-16

CREATE TABLE email_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
```

### Down Migration (Optional)
Contains SQL statements to rollback the change:

```sql
-- Migration: add_email_templates
-- Created: 2025-10-16

DROP TABLE IF EXISTS email_templates;
```

## Checking Migration Status

To see which migrations have been applied:

```bash
make migrate-status
```

This queries the `schema_migrations` table and shows:
- Version number
- Migration name
- When it was applied

## Migration Tracking

The application maintains a `schema_migrations` table:

```sql
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
```

This table tracks which migrations have been applied to the database.

## Best Practices

1. **Never modify applied migrations** - Once a migration has been applied to any environment, create a new migration to make changes

2. **Test migrations** - Always test both up and down migrations before deploying

3. **Keep migrations small** - Break large schema changes into multiple migrations

4. **Make migrations reversible** - Always provide a down migration when possible

5. **Use transactions** - The migration runner automatically wraps each migration in a transaction

6. **Add indexes** - Create indexes in separate migrations for performance monitoring

7. **Data migrations** - For data transformations, create a separate migration after schema changes

## Example Migration Workflow

1. Create new migration:
   ```bash
   make migrate-create NAME=add_user_preferences
   ```

2. Edit the generated files:
   - `pkg/migrations/files/009_add_user_preferences.up.sql`
   - `pkg/migrations/files/009_add_user_preferences.down.sql`

3. Commit the files to version control

4. The migration will automatically run when:
   - Any developer starts the server
   - The application is deployed to staging/production

## Troubleshooting

### Migration failed during startup

If a migration fails, the application won't start. Check the logs for:
```
failed to run database migrations: <error>
```

To fix:
1. Identify the problematic migration from the logs
2. Fix the SQL in the migration file
3. Manually rollback if needed (see manual rollback below)
4. Restart the application

### Manual rollback (if needed)

In rare cases, you may need to manually rollback:

```sql
-- Connect to database
psql $DATABASE_URL

-- Check current version
SELECT version, name, applied_at FROM schema_migrations ORDER BY version DESC LIMIT 5;

-- Manually run down migration SQL (from the .down.sql file)
-- Then remove the version from tracking table
DELETE FROM schema_migrations WHERE version = 9;
```

### Check migration files

```bash
# List all migration files
make migrate-list

# View migration directory
ls -la pkg/migrations/files/
```

## Notes

- Migrations run in a transaction - if any step fails, the entire migration is rolled back
- Only pending migrations (version > current version) are applied
- Migrations are applied in ascending order by version number
- The migration runner logs detailed information about each migration applied
