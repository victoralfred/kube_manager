-- Remove default permissions
DELETE FROM permissions WHERE description IN (
    'Create new tenants', 'View tenant information', 'Update tenant information', 'Delete tenants',
    'Suspend tenant access', 'Activate suspended tenants',
    'Create new users', 'View user information', 'Update user information', 'Delete users', 'Assign roles to users',
    'Create new roles', 'View role information', 'Update role information', 'Delete roles',
    'Create new permissions', 'View permission information', 'Delete permissions',
    'Create new resources', 'View resource information', 'Update resource information', 'Delete resources',
    'View audit logs',
    'Create new policies', 'View policy information', 'Update policy information', 'Delete policies'
);
