-- migrate:up
-- The earlier bootstrap migration inserted this account with a public,
-- non-Argon2 password value. Remove it and its dependent sessions/tokens.
DELETE FROM users WHERE lower(email) = lower('demo@example.com');

-- migrate:down
-- Intentionally do not restore a demo credential. Recreate users through
-- the normal registration or administrative provisioning flow.
SELECT 1;
