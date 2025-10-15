-- Create permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(resource, action)
);

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(50) NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP,
    UNIQUE(tenant_id, slug),
    CONSTRAINT fk_roles_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create role_permissions junction table
CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(role_id, permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- Create user_roles table (already exists in auth migration, but ensuring it's here for clarity)
-- Note: This assumes the users table exists from auth migration
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by UUID,
    UNIQUE(user_id, role_id, tenant_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_roles_slug ON roles(slug) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_roles_is_system ON roles(is_system) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_tenant_id ON user_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);

-- Insert default permissions
INSERT INTO permissions (resource, action, description) VALUES
    -- Tenant permissions
    ('tenant', 'create', 'Create new tenants'),
    ('tenant', 'read', 'View tenant details'),
    ('tenant', 'update', 'Update tenant information'),
    ('tenant', 'delete', 'Delete tenants'),
    ('tenant', 'list', 'List all tenants'),
    ('tenant', 'manage', 'Full tenant management'),

    -- User permissions
    ('user', 'create', 'Create new users'),
    ('user', 'read', 'View user details'),
    ('user', 'update', 'Update user information'),
    ('user', 'delete', 'Delete users'),
    ('user', 'list', 'List all users'),
    ('user', 'manage', 'Full user management'),

    -- Role permissions
    ('role', 'create', 'Create new roles'),
    ('role', 'read', 'View role details'),
    ('role', 'update', 'Update role information'),
    ('role', 'delete', 'Delete roles'),
    ('role', 'list', 'List all roles'),
    ('role', 'manage', 'Full role management'),

    -- Resource permissions
    ('resource', 'create', 'Create new resources'),
    ('resource', 'read', 'View resource details'),
    ('resource', 'update', 'Update resource information'),
    ('resource', 'delete', 'Delete resources'),
    ('resource', 'list', 'List all resources'),
    ('resource', 'manage', 'Full resource management'),

    -- Audit log permissions
    ('audit_log', 'read', 'View audit logs'),
    ('audit_log', 'list', 'List audit logs'),
    ('audit_log', 'export', 'Export audit logs')
ON CONFLICT (resource, action) DO NOTHING;

-- Function to create system roles for a tenant
CREATE OR REPLACE FUNCTION create_system_roles_for_tenant(p_tenant_id UUID)
RETURNS VOID AS $$
DECLARE
    v_admin_role_id UUID;
    v_user_role_id UUID;
    v_viewer_role_id UUID;
    v_moderator_role_id UUID;
    v_permission_id UUID;
BEGIN
    -- Create admin role
    INSERT INTO roles (tenant_id, name, slug, description, is_system)
    VALUES (p_tenant_id, 'Administrator', 'admin', 'Full system access', TRUE)
    RETURNING id INTO v_admin_role_id;

    -- Assign all permissions to admin
    FOR v_permission_id IN SELECT id FROM permissions
    LOOP
        INSERT INTO role_permissions (role_id, permission_id)
        VALUES (v_admin_role_id, v_permission_id);
    END LOOP;

    -- Create user role
    INSERT INTO roles (tenant_id, name, slug, description, is_system)
    VALUES (p_tenant_id, 'User', 'user', 'Standard user access', TRUE)
    RETURNING id INTO v_user_role_id;

    -- Assign basic permissions to user
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_user_role_id, id FROM permissions
    WHERE (resource = 'user' AND action IN ('read', 'update'))
       OR (resource = 'tenant' AND action = 'read')
       OR (resource = 'resource' AND action IN ('create', 'read', 'update', 'delete', 'list'));

    -- Create viewer role
    INSERT INTO roles (tenant_id, name, slug, description, is_system)
    VALUES (p_tenant_id, 'Viewer', 'viewer', 'Read-only access', TRUE)
    RETURNING id INTO v_viewer_role_id;

    -- Assign read permissions to viewer
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_viewer_role_id, id FROM permissions
    WHERE action IN ('read', 'list');

    -- Create moderator role
    INSERT INTO roles (tenant_id, name, slug, description, is_system)
    VALUES (p_tenant_id, 'Moderator', 'moderator', 'Moderate users and content', TRUE)
    RETURNING id INTO v_moderator_role_id;

    -- Assign moderation permissions
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_moderator_role_id, id FROM permissions
    WHERE (resource IN ('user', 'resource') AND action IN ('read', 'update', 'list'))
       OR (resource = 'audit_log' AND action IN ('read', 'list'));

END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically create system roles for new tenants
CREATE OR REPLACE FUNCTION trigger_create_system_roles()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM create_system_roles_for_tenant(NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER after_tenant_insert_create_roles
AFTER INSERT ON tenants
FOR EACH ROW
EXECUTE FUNCTION trigger_create_system_roles();
