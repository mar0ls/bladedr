-- Workflow status must never implicitly label training data.
ALTER TABLE observations ADD COLUMN verdict text NOT NULL DEFAULT 'unknown'
 CHECK (verdict IN ('unknown','true_positive','false_positive'));
CREATE INDEX observations_verdict_cursor ON observations(verdict,last_seen DESC,id DESC);
