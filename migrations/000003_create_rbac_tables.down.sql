-- Drop trigger
DROP TRIGGER IF EXISTS after_tenant_insert_create_roles ON tenants;

-- Drop functions
DROP FUNCTION IF EXISTS trigger_create_system_roles();
DROP FUNCTION IF EXISTS create_system_roles_for_tenant(UUID);

-- Drop tables in correct order (respecting foreign keys)
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;
