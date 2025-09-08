-- Add first_login column to users table
ALTER TABLE users 
ADD COLUMN first_login BOOLEAN NOT NULL DEFAULT FALSE;
ADD COLUMN reset_password BOOLEAN NOT NULL DEFAULT FALSE;

-- Create groups table
CREATE TABLE IF NOT EXISTS groups (
    group_id BIGSERIAL PRIMARY KEY,
    external_id UUID NOT NULL DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS groups_external_id_idx ON groups (external_id);
CREATE UNIQUE INDEX IF NOT EXISTS groups_name_idx ON groups (name);

-- Create policies table
CREATE TABLE IF NOT EXISTS policies (
    policy_id BIGSERIAL PRIMARY KEY,
    external_id UUID NOT NULL DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    resource VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    effect VARCHAR(10) NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
    conditions JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS policies_external_id_idx ON policies (external_id);
CREATE UNIQUE INDEX IF NOT EXISTS policies_name_idx ON policies (name);
CREATE INDEX IF NOT EXISTS policies_resource_action_idx ON policies (resource, action);

-- Create user_groups table (many-to-many)
CREATE TABLE IF NOT EXISTS user_groups (
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by BIGINT REFERENCES users(user_id),
    PRIMARY KEY (user_id, group_id)
);

-- Create user_policies table (many-to-many)
CREATE TABLE IF NOT EXISTS user_policies (
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    policy_id BIGINT NOT NULL REFERENCES policies(policy_id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by BIGINT REFERENCES users(user_id),
    PRIMARY KEY (user_id, policy_id)
);

-- Create group_policies table (many-to-many)
CREATE TABLE IF NOT EXISTS group_policies (
    group_id BIGINT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    policy_id BIGINT NOT NULL REFERENCES policies(policy_id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by BIGINT REFERENCES users(user_id),
    PRIMARY KEY (group_id, policy_id)
);

-- Create password_reset_tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS password_reset_tokens_token_idx ON password_reset_tokens (token);
CREATE INDEX IF NOT EXISTS password_reset_tokens_user_id_idx ON password_reset_tokens (user_id);

-- Add triggers for updated_at
CREATE TRIGGER trg_set_updated_at_groups
BEFORE UPDATE ON groups
FOR EACH ROW
EXECUTE PROCEDURE set_updated_at();

CREATE TRIGGER trg_set_updated_at_policies
BEFORE UPDATE ON policies
FOR EACH ROW
EXECUTE PROCEDURE set_updated_at();

-- Insert default admin user and groups/policies
INSERT INTO users (email, username, password_hash, first_login) VALUES 
    ('admin@admin.com', 'admin', '$argon2id$v=19$m=19456,t=2,p=1$+DUxbVoOcmKBMd4ajKp3Tg$c1UkZ8/fW3sKvOhhEqYCwZ8gLj5M7SqGOEcZYbCf5gg', TRUE)
ON CONFLICT (email) DO NOTHING;

-- Insert default groups
INSERT INTO groups (name, description) VALUES 
    ('superadmin', 'Super administrators with full access'),
    ('users', 'Regular users')
ON CONFLICT (name) DO NOTHING;

-- Insert default policies
INSERT INTO policies (name, description, resource, action, effect) VALUES 
    ('full_access', 'Full access to all resources', '*', '*', 'ALLOW'),
    ('read_only', 'Read-only access to user resources', 'user:*', 'read', 'ALLOW'),
    ('user_self_manage', 'Users can manage their own data', 'user:self', '*', 'ALLOW')
ON CONFLICT (name) DO NOTHING;

-- Assign admin user to superadmin group
INSERT INTO user_groups (user_id, group_id) 
SELECT u.user_id, g.group_id 
FROM users u, groups g 
WHERE u.username = 'admin' AND g.name = 'superadmin'
ON CONFLICT DO NOTHING;

-- Assign full_access policy to superadmin group
INSERT INTO group_policies (group_id, policy_id) 
SELECT g.group_id, p.policy_id 
FROM groups g, policies p 
WHERE g.name = 'superadmin' AND p.name = 'full_access'
ON CONFLICT DO NOTHING;

-- Assign read_only and user_self_manage policies to users group
INSERT INTO group_policies (group_id, policy_id) 
SELECT g.group_id, p.policy_id 
FROM groups g, policies p 
WHERE g.name = 'users' AND p.name IN ('read_only', 'user_self_manage')
ON CONFLICT DO NOTHING;
