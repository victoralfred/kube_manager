-- Create function to auto-create default roles for new tenants
CREATE OR REPLACE FUNCTION create_default_tenant_roles()
RETURNS TRIGGER AS $$
BEGIN
    -- Create Admin role
    INSERT INTO roles (id, tenant_id, name, slug, description, is_system, created_at, updated_at)
    VALUES (
        uuid_generate_v4(),
        NEW.id,
        'Admin',
        'admin',
        'Full administrative access to all resources',
        true,
        NOW(),
        NOW()
    );

    -- Create User role
    INSERT INTO roles (id, tenant_id, name, slug, description, is_system, created_at, updated_at)
    VALUES (
        uuid_generate_v4(),
        NEW.id,
        'User',
        'user',
        'Standard user access with limited permissions',
        true,
        NOW(),
        NOW()
    );

    -- Create Viewer role
    INSERT INTO roles (id, tenant_id, name, slug, description, is_system, created_at, updated_at)
    VALUES (
        uuid_generate_v4(),
        NEW.id,
        'Viewer',
        'viewer',
        'Read-only access to resources',
        true,
        NOW(),
        NOW()
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to execute function after tenant insert
CREATE TRIGGER trigger_create_default_tenant_roles
    AFTER INSERT ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION create_default_tenant_roles();

-- Add comment explaining the trigger
COMMENT ON TRIGGER trigger_create_default_tenant_roles ON tenants IS
'Automatically creates default roles (Admin, User, Viewer) when a new tenant is created';
