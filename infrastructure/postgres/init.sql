-- Initial PostgreSQL setup for Security Portal
-- Run automatically on first postgres container start

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- for LIKE search performance
CREATE EXTENSION IF NOT EXISTS "btree_gin"; -- for JSON index support

-- Ensure the database uses UTC timestamps
SET timezone = 'UTC';
