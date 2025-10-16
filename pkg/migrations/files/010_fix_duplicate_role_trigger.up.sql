-- Fix duplicate role creation triggers
-- Migration 008 created a broken trigger that conflicts with the correct one from migration 003
-- This migration removes the broken trigger

-- Drop the broken trigger and function from migration 008
DROP TRIGGER IF EXISTS trigger_create_default_tenant_roles ON tenants;
DROP FUNCTION IF EXISTS create_default_tenant_roles();

-- Ensure the correct trigger from migration 003 exists
-- (It should already exist, but recreating just in case)
CREATE OR REPLACE FUNCTION trigger_create_system_roles()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM create_system_roles_for_tenant(NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Drop and recreate the correct trigger to ensure it's active
DROP TRIGGER IF EXISTS after_tenant_insert_create_roles ON tenants;

CREATE TRIGGER after_tenant_insert_create_roles
AFTER INSERT ON tenants
FOR EACH ROW
EXECUTE FUNCTION trigger_create_system_roles();

-- Add comment
COMMENT ON TRIGGER after_tenant_insert_create_roles ON tenants IS
'Automatically creates system roles (Administrator, User, Viewer) with proper role_type when a new tenant is created';
