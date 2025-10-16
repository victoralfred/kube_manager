-- ================================================================
-- RBAC System Rollback Migration
-- ================================================================

-- Drop trigger
DROP TRIGGER IF EXISTS after_tenant_insert_create_roles ON tenants;

-- Drop functions
DROP FUNCTION IF EXISTS trigger_create_system_roles();
DROP FUNCTION IF EXISTS create_system_roles_for_tenant(UUID);

-- Drop tables in reverse order (respecting foreign key constraints)
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS role_permissions CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS resource_registry CASCADE;
DROP TABLE IF EXISTS permissions CASCADE;
