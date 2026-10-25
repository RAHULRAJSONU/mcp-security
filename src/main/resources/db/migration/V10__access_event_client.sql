-- Which registered agent (OAuth client) made the call, so the trail answers
-- "the user, or an agent acting for the user?". NULL for rows written before this.
ALTER TABLE access_events ADD COLUMN client_id VARCHAR(128);
