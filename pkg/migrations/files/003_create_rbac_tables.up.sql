-- ================================================================
-- RBAC System Migration: Production-Ready Template-Based Permissions
-- ================================================================

-- Permission Templates (NO tenant_id duplication)
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    scope VARCHAR(20) NOT NULL CHECK (scope IN ('system', 'tenant')),
    requires_ownership BOOLEAN DEFAULT FALSE,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(resource, action)
);

CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_scope ON permissions(scope);

-- Roles (tenant-scoped with type classification)
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID, -- NULL for platform roles
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(50) NOT NULL,
    description TEXT,
    role_type VARCHAR(20) NOT NULL CHECK (role_type IN ('platform', 'system', 'custom')),
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP,
    UNIQUE(tenant_id, slug),
    CONSTRAINT fk_roles_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_roles_type ON roles(role_type) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_roles_slug ON roles(slug) WHERE deleted_at IS NULL;

-- Role-Permission assignments with optional ABAC conditions
CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    conditions JSONB, -- Optional ABAC conditions
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(role_id, permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);

-- User-Role assignments
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

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_tenant ON user_roles(tenant_id);

-- Resource Registry (dynamic resource definitions)
CREATE TABLE IF NOT EXISTS resource_registry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    scope VARCHAR(20) NOT NULL CHECK (scope IN ('system', 'tenant')),
    tenant_id UUID, -- NULL for system resources, specific for tenant custom resources
    actions TEXT[], -- Array of supported actions
    created_by VARCHAR(20) NOT NULL, -- 'system' or 'tenant_admin'
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(name, tenant_id),
    CONSTRAINT fk_resource_registry_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_resource_registry_scope ON resource_registry(scope);
CREATE INDEX IF NOT EXISTS idx_resource_registry_tenant ON resource_registry(tenant_id);

-- ================================================================
-- Seed Data: System Permission Templates
-- ================================================================

-- System Permission Templates (Core Resources)
INSERT INTO permissions (resource, action, scope, requires_ownership, description) VALUES
-- Tenant management (system scope)
('tenant', 'create', 'system', false, 'Create new tenants'),
('tenant', 'delete', 'system', false, 'Delete tenants'),
('tenant', 'list', 'system', false, 'List all tenants'),
('tenant', 'suspend', 'system', false, 'Suspend tenants'),

-- Tenant operations (tenant scope)
('tenant', 'read', 'tenant', false, 'View tenant details'),
('tenant', 'update', 'tenant', false, 'Update tenant information'),

-- User management (tenant scope)
('user', 'create', 'tenant', false, 'Create new users'),
('user', 'read', 'tenant', false, 'View user details'),
('user', 'update', 'tenant', true, 'Update user information'),
('user', 'delete', 'tenant', false, 'Delete users'),
('user', 'list', 'tenant', false, 'List all users'),

-- Role management (tenant scope)
('role', 'create', 'tenant', false, 'Create custom roles'),
('role', 'read', 'tenant', false, 'View role details'),
('role', 'update', 'tenant', false, 'Update role information'),
('role', 'delete', 'tenant', false, 'Delete custom roles'),
('role', 'list', 'tenant', false, 'List all roles'),
('role', 'assign', 'tenant', false, 'Assign roles to users'),

-- Resource management (tenant scope)
('resource', 'create', 'tenant', true, 'Create resources'),
('resource', 'read', 'tenant', true, 'View resources'),
('resource', 'update', 'tenant', true, 'Update resources'),
('resource', 'delete', 'tenant', true, 'Delete resources'),
('resource', 'list', 'tenant', false, 'List resources')
ON CONFLICT (resource, action) DO NOTHING;

-- Register core resources
INSERT INTO resource_registry (name, description, scope, actions, created_by) VALUES
('tenant', 'Tenant management', 'system', ARRAY['create', 'read', 'update', 'delete', 'list', 'suspend'], 'system'),
('user', 'User management', 'tenant', ARRAY['create', 'read', 'update', 'delete', 'list'], 'system'),
('role', 'Role management', 'tenant', ARRAY['create', 'read', 'update', 'delete', 'list', 'assign'], 'system'),
('resource', 'Resource management', 'tenant', ARRAY['create', 'read', 'update', 'delete', 'list'], 'system')
ON CONFLICT (name, tenant_id) DO NOTHING;

-- ================================================================
-- System Role Auto-Creation Function
-- ================================================================

-- Function to create system roles for each tenant
CREATE OR REPLACE FUNCTION create_system_roles_for_tenant(p_tenant_id UUID)
RETURNS VOID AS $$
DECLARE
    v_admin_role_id UUID;
    v_user_role_id UUID;
    v_viewer_role_id UUID;
BEGIN
    -- Create Admin role (full tenant access)
    INSERT INTO roles (tenant_id, name, slug, description, role_type, is_system)
    VALUES (p_tenant_id, 'Administrator', 'admin', 'Full access within tenant', 'system', TRUE)
    RETURNING id INTO v_admin_role_id;

    -- Assign ALL tenant-scoped permissions to admin
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_admin_role_id, id FROM permissions WHERE scope = 'tenant'
    ON CONFLICT (role_id, permission_id) DO NOTHING;

    -- Create User role (standard access)
    INSERT INTO roles (tenant_id, name, slug, description, role_type, is_system)
    VALUES (p_tenant_id, 'User', 'user', 'Standard user access', 'system', TRUE)
    RETURNING id INTO v_user_role_id;

    -- Assign basic permissions to user
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_user_role_id, id FROM permissions
    WHERE (resource = 'user' AND action IN ('read', 'update'))
       OR (resource = 'tenant' AND action = 'read')
       OR (resource = 'resource' AND action IN ('create', 'read', 'update', 'delete', 'list'))
    ON CONFLICT (role_id, permission_id) DO NOTHING;

    -- Create Viewer role (read-only)
    INSERT INTO roles (tenant_id, name, slug, description, role_type, is_system)
    VALUES (p_tenant_id, 'Viewer', 'viewer', 'Read-only access', 'system', TRUE)
    RETURNING id INTO v_viewer_role_id;

    -- Assign read permissions to viewer
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_viewer_role_id, id FROM permissions
    WHERE scope = 'tenant' AND action IN ('read', 'list')
    ON CONFLICT (role_id, permission_id) DO NOTHING;

END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-create roles for new tenants
CREATE OR REPLACE FUNCTION trigger_create_system_roles()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM create_system_roles_for_tenant(NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Drop existing trigger if it exists
DROP TRIGGER IF EXISTS after_tenant_insert_create_roles ON tenants;

-- Create trigger
CREATE TRIGGER after_tenant_insert_create_roles
AFTER INSERT ON tenants
FOR EACH ROW
EXECUTE FUNCTION trigger_create_system_roles();
