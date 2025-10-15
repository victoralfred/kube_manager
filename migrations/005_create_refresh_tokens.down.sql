-- Drop function
DROP FUNCTION IF EXISTS clean_expired_refresh_tokens();

-- Drop refresh_tokens table
DROP TABLE IF EXISTS refresh_tokens CASCADE;
