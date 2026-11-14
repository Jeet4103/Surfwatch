-- migrate:up
CREATE TABLE IF NOT EXISTS organization_members (
    organization_id INTEGER NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id),
    CONSTRAINT organization_members_status_chk CHECK (status IN ('invited', 'active', 'suspended'))
);

CREATE INDEX IF NOT EXISTS organization_members_user_idx ON organization_members (user_id);

INSERT INTO organization_members (organization_id, user_id, status)
SELECT o.id, u.id, 'active'
FROM organizations o
CROSS JOIN users u
WHERE lower(o.slug) = lower('demo-organization')
  AND lower(u.email) = lower('demo@example.com')
ON CONFLICT (organization_id, user_id) DO NOTHING;

-- migrate:down
DROP INDEX IF EXISTS organization_members_user_idx;
DROP TABLE IF EXISTS organization_members;