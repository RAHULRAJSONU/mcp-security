package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.rahulrajsonu.mcpsecurity.security.AccessPurpose;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

class PatientMcpToolsTest {

    @Test
    void defaultsToTreatment() {
        assertThat(PatientMcpTools.parsePurpose(null)).isEqualTo(AccessPurpose.TREATMENT);
        assertThat(PatientMcpTools.parsePurpose("  ")).isEqualTo(AccessPurpose.TREATMENT);
    }

    @Test
    void parsesPurposeCaseInsensitively() {
        assertThat(PatientMcpTools.parsePurpose(" emergency ")).isEqualTo(AccessPurpose.EMERGENCY);
    }

    @Test
    void unknownPurposeIsRefusedWithoutEchoingInput() {
        assertThatThrownBy(() -> PatientMcpTools.parsePurpose("<script>alert(1)</script>"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageNotContaining("script");
    }
}
