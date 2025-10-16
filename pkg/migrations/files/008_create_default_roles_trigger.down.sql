-- Drop trigger
DROP TRIGGER IF EXISTS trigger_create_default_tenant_roles ON tenants;

-- Drop function
DROP FUNCTION IF EXISTS create_default_tenant_roles();
