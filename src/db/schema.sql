-- ==============================================================================
-- Cybersecurity Incident Triage AI - Supabase PostgreSQL Schema
-- Table: incidents
-- Description: Stores persistent incident triage analyses and synthesized reports.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    alert_text TEXT NOT NULL,
    severity TEXT,
    event_type TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    destination_port TEXT,
    iocs JSONB DEFAULT '[]'::jsonb,
    threat_intelligence JSONB DEFAULT '[]'::jsonb,
    mitre_results JSONB DEFAULT '[]'::jsonb,
    playbooks JSONB DEFAULT '[]'::jsonb,
    cisa_guidance JSONB DEFAULT '[]'::jsonb,
    triage_report JSONB NOT NULL,
    analyst_review_required BOOLEAN DEFAULT true
);

-- Index on created_at for fast descending history queries
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at DESC);

-- Index on incident_id for fast lookup
CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON incidents (incident_id);

-- Row-Level Security (RLS) configuration
-- Enforce RLS so direct public/anon access cannot modify or inject records.
-- Only the backend service role is granted full access.
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;

-- Drop any previous permissive policies to guarantee strict isolation
DROP POLICY IF EXISTS "Allow service role full access" ON incidents;
DROP POLICY IF EXISTS "Allow anon read" ON incidents;
DROP POLICY IF EXISTS "Allow anon insert" ON incidents;

-- Policy: Allow service role full access (FastAPI backend persistence)
CREATE POLICY "Allow service role full access" 
ON incidents 
FOR ALL 
TO service_role 
USING (true) 
WITH CHECK (true);

