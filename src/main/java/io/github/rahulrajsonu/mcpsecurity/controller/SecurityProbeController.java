package io.github.rahulrajsonu.mcpsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile("oauth-demo")
public class SecurityProbeController {

    @GetMapping("/api/security/probe")
    public String probe() {
        return "Healthcare API reachable";
    }
}