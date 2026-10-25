package io.github.rahulrajsonu.mcpsecurity.config;

import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolErrors;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
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
    static BeanPostProcessor sanitizeToolErrors() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof List<?> list
                        && !list.isEmpty()
                        && list.stream().allMatch(SyncToolSpecification.class::isInstance)) {
                    return list.stream()
                            .map(SyncToolSpecification.class::cast)
                            .peek(spec -> LOG.info("mcp_tool_fingerprint name={} sha256={}",
                                    spec.tool().name(), ToolErrors.fingerprint(spec)))
                            .map(ToolErrors::sanitized)
                            .toList();
                }
                return bean;
            }
        };
    }
}
