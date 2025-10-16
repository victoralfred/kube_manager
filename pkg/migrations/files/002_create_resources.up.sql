-- Create resources table
CREATE TABLE IF NOT EXISTS resources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'provisioning',
    storage_used BIGINT DEFAULT 0,
    cpu_allocated DECIMAL(10, 2) DEFAULT 0.0,
    memory_allocated BIGINT DEFAULT 0,
    configuration JSONB DEFAULT '{}'::jsonb,
    tags TEXT[],
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT chk_resource_type CHECK (type IN ('compute', 'storage', 'database', 'network', 'kubernetes', 'container')),
    CONSTRAINT chk_resource_status CHECK (status IN ('active', 'provisioning', 'suspended', 'terminated', 'error')),
    CONSTRAINT chk_storage_used CHECK (storage_used >= 0),
    CONSTRAINT chk_cpu_allocated CHECK (cpu_allocated >= 0),
    CONSTRAINT chk_memory_allocated CHECK (memory_allocated >= 0)
);

-- Create indexes on resources
CREATE INDEX idx_resources_tenant_id ON resources(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_resources_type ON resources(type) WHERE deleted_at IS NULL;
CREATE INDEX idx_resources_status ON resources(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_resources_created_by ON resources(created_by);
CREATE INDEX idx_resources_tags ON resources USING GIN(tags);
CREATE INDEX idx_resources_created_at ON resources(created_at DESC);
