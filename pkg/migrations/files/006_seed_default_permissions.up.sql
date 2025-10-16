-- Migration 006: Additional permission seeding
-- NOTE: Migration 003 already seeds core permissions, so this adds any additional ones

-- Insert additional system permissions with proper scope
INSERT INTO permissions (id, resource, action, scope, requires_ownership, description) VALUES
-- Additional tenant permissions (system scope)
(gen_random_uuid(), 'tenant', 'activate', 'system', false, 'Activate suspended tenants'),

-- Additional user permissions (tenant scope)
(gen_random_uuid(), 'user', 'assign_roles', 'tenant', false, 'Assign roles to users'),

-- Permission management (tenant scope - for admins to manage custom permissions)
(gen_random_uuid(), 'permission', 'create', 'tenant', false, 'Create new permissions'),
(gen_random_uuid(), 'permission', 'read', 'tenant', false, 'View permission information'),
(gen_random_uuid(), 'permission', 'delete', 'tenant', false, 'Delete permissions'),

-- Audit log permissions (tenant scope)
(gen_random_uuid(), 'audit_log', 'read', 'tenant', false, 'View audit logs'),

-- Policy permissions (tenant scope)
(gen_random_uuid(), 'policy', 'create', 'tenant', false, 'Create new policies'),
(gen_random_uuid(), 'policy', 'read', 'tenant', false, 'View policy information'),
(gen_random_uuid(), 'policy', 'update', 'tenant', false, 'Update policy information'),
(gen_random_uuid(), 'policy', 'delete', 'tenant', false, 'Delete policies')
ON CONFLICT (resource, action) DO NOTHING;

-- Register additional resources
INSERT INTO resource_registry (name, description, scope, actions, created_by) VALUES
('audit_log', 'Audit log management', 'tenant', ARRAY['read'], 'system'),
('policy', 'Policy management', 'tenant', ARRAY['create', 'read', 'update', 'delete'], 'system'),
('permission', 'Permission management', 'tenant', ARRAY['create', 'read', 'delete'], 'system')
ON CONFLICT (name, tenant_id) DO NOTHING;
