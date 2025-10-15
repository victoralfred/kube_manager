-- Create policies table
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    effect VARCHAR(10) NOT NULL,
    rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_policy_effect CHECK (effect IN ('allow', 'deny')),
    CONSTRAINT uq_policy_name_tenant UNIQUE (tenant_id, name)
);

-- Create indexes on policies
CREATE INDEX idx_policies_tenant_id ON policies(tenant_id);
CREATE INDEX idx_policies_effect ON policies(effect);
CREATE INDEX idx_policies_priority ON policies(priority DESC);

-- Create policy_roles junction table (policies applied to roles)
CREATE TABLE IF NOT EXISTS policy_roles (
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (policy_id, role_id)
);

-- Create indexes on policy_roles
CREATE INDEX idx_policy_roles_policy_id ON policy_roles(policy_id);
CREATE INDEX idx_policy_roles_role_id ON policy_roles(role_id);
