-- Insert default system permissions
INSERT INTO permissions (id, resource, action, description) VALUES
-- Tenant permissions
(uuid_generate_v4(), 'tenants', 'create', 'Create new tenants'),
(uuid_generate_v4(), 'tenants', 'read', 'View tenant information'),
(uuid_generate_v4(), 'tenants', 'update', 'Update tenant information'),
(uuid_generate_v4(), 'tenants', 'delete', 'Delete tenants'),
(uuid_generate_v4(), 'tenants', 'suspend', 'Suspend tenant access'),
(uuid_generate_v4(), 'tenants', 'activate', 'Activate suspended tenants'),

-- User permissions
(uuid_generate_v4(), 'users', 'create', 'Create new users'),
(uuid_generate_v4(), 'users', 'read', 'View user information'),
(uuid_generate_v4(), 'users', 'update', 'Update user information'),
(uuid_generate_v4(), 'users', 'delete', 'Delete users'),
(uuid_generate_v4(), 'users', 'assign_roles', 'Assign roles to users'),

-- Role permissions
(uuid_generate_v4(), 'roles', 'create', 'Create new roles'),
(uuid_generate_v4(), 'roles', 'read', 'View role information'),
(uuid_generate_v4(), 'roles', 'update', 'Update role information'),
(uuid_generate_v4(), 'roles', 'delete', 'Delete roles'),

-- Permission permissions
(uuid_generate_v4(), 'permissions', 'create', 'Create new permissions'),
(uuid_generate_v4(), 'permissions', 'read', 'View permission information'),
(uuid_generate_v4(), 'permissions', 'delete', 'Delete permissions'),

-- Resource permissions
(uuid_generate_v4(), 'resources', 'create', 'Create new resources'),
(uuid_generate_v4(), 'resources', 'read', 'View resource information'),
(uuid_generate_v4(), 'resources', 'update', 'Update resource information'),
(uuid_generate_v4(), 'resources', 'delete', 'Delete resources'),

-- Audit log permissions
(uuid_generate_v4(), 'audit_logs', 'read', 'View audit logs'),

-- Policy permissions
(uuid_generate_v4(), 'policies', 'create', 'Create new policies'),
(uuid_generate_v4(), 'policies', 'read', 'View policy information'),
(uuid_generate_v4(), 'policies', 'update', 'Update policy information'),
(uuid_generate_v4(), 'policies', 'delete', 'Delete policies')
ON CONFLICT (resource, action) DO NOTHING;
