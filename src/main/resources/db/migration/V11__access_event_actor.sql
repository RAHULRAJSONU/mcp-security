-- Who was acting for the user when more than one agent was in the chain (RFC 8693 `act`),
-- outermost first, e.g. "agent-a>agent-b". NULL when the user's own client called directly.
ALTER TABLE access_events ADD COLUMN actor VARCHAR(256);
