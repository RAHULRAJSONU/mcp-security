package io.github.rahulrajsonu.mcpsecurity.config;

import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolErrors;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.McpStatelessServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Wraps every registered tool so a failed call reaches the model as the
 * sanitized {@code ToolCallResponse} instead of the framework's raw text.
 */
@Configuration
public class McpToolErrorConfig {

    private static final Logger LOG = LoggerFactory.getLogger(McpToolErrorConfig.class);

    @Bean
    static BeanPostProcessor sanitizeToolErrors(ObjectProvider<MeterRegistry> meters) {
        // Resolved on first call, not at startup, so this early bean does not pull in the registry.
        ToolMetrics metrics = new ToolMetrics(meters::getIfAvailable);

        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (!(bean instanceof List<?> list) || list.isEmpty()) {
                    return bean;
                }
                if (list.stream().allMatch(SyncToolSpecification.class::isInstance)) {
                    return list.stream()
                            .map(SyncToolSpecification.class::cast)
                            .peek(spec -> logFingerprint(spec.tool()))
                            .map(spec -> ToolErrors.sanitized(spec, metrics))
                            .toList();
                }
                if (list.stream().allMatch(McpStatelessServerFeatures.SyncToolSpecification.class::isInstance)) {
                    return list.stream()
                            .map(McpStatelessServerFeatures.SyncToolSpecification.class::cast)
                            .peek(spec -> logFingerprint(spec.tool()))
                            .map(spec -> ToolErrors.sanitized(spec, metrics))
                            .toList();
                }
                return bean;
            }
        };
    }

    private static void logFingerprint(McpSchema.Tool tool) {
        LOG.info("mcp_tool_fingerprint name={} sha256={}", tool.name(), ToolErrors.fingerprint(tool));
    }
}
