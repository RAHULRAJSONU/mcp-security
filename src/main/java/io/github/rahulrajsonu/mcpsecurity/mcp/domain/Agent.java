package io.github.rahulrajsonu.mcpsecurity.mcp.domain;

import java.time.Instant;

public record Agent(String clientId, AgentState state, Instant expiresAt) {
}
