-- ================================================================
-- Migration 009: Align User Schema with OpenAPI Specification
-- ================================================================

-- Add missing columns to users table
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS username VARCHAR(50) UNIQUE,
  ADD COLUMN IF NOT EXISTS phone VARCHAR(20),
  ADD COLUMN IF NOT EXISTS avatar_url TEXT,
  ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- Create indexes on new columns
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE deleted_at IS NULL AND username IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone) WHERE deleted_at IS NULL AND phone IS NOT NULL;

-- Update status values to match OpenAPI spec
-- OpenAPI: 'active', 'pending', 'inactive', 'suspended'
-- Current: 'active', 'pending_verification', 'suspended', 'deleted'

-- Migrate 'pending_verification' to 'pending'
UPDATE users SET status = 'pending' WHERE status = 'pending_verification';

-- Note: 'deleted' status should use deleted_at timestamp instead
-- But we'll keep it for backward compatibility and add 'inactive' support

-- Drop existing status constraint if it exists
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_status_check;

-- Add new constraint with updated values
ALTER TABLE users
  ADD CONSTRAINT users_status_check
  CHECK (status IN ('active', 'pending', 'inactive', 'suspended', 'deleted'));

-- Comment on new columns
COMMENT ON COLUMN users.username IS 'Unique username for the user (optional, can be null)';
COMMENT ON COLUMN users.phone IS 'User phone number in international format';
COMMENT ON COLUMN users.avatar_url IS 'URL to user avatar/profile picture';
COMMENT ON COLUMN users.metadata IS 'Additional user metadata stored as JSONB';
COMMENT ON COLUMN users.status IS 'User status: active, pending (email not verified), inactive, suspended, or deleted';
