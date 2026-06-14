package dev.sandipchitale.oidcoauth2.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class ResourceController {

    @GetMapping("/get")
    public Map<String, Object> getResource(Authentication authentication) {
        return Map.of(
                "status", "success",
                "endpoint", "/get",
                "requiredScope", "READ",
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities().toString()
        );
    }

    @PostMapping("/post")
    public Map<String, Object> postResource(Authentication authentication, @RequestBody(required = false) Map<String, Object> body) {
        return Map.of(
                "status", "success",
                "endpoint", "/post",
                "requiredScope", "WRITE",
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities().toString(),
                "payload", body != null ? body : Map.of()
        );
    }

    // Authentication-only endpoint (NO scope required). Any token whose audience is bound to this resource
    // server is accepted — including a zero-scope, least-privilege token. Demonstrates: audience = "may I
    // enter?"; scope = "may I do X?". A minimal token gets in here but is rejected by /get and /post.
    @GetMapping("/whoami")
    public Map<String, Object> whoami(Authentication authentication, @AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> body = new HashMap<>();
        body.put("status", "success");
        body.put("endpoint", "/whoami");
        body.put("requiredScope", "(none — authentication only)");
        body.put("subject", jwt.getSubject());
        body.put("username", authentication.getName());
        body.put("authorities", authentication.getAuthorities().toString());
        Object scope = jwt.getClaims().get("scope");
        body.put("token_scope", scope != null ? scope : "(none)");
        body.put("token_aud", jwt.getAudience());
        return body;
    }

    // Authentication-only endpoint (NO scope required). Identifies the resource server and confirms the
    // token's audience is bound to it (the audience-validating decoder already enforced this at the door).
    @GetMapping("/whereami")
    public Map<String, Object> whereami(@AuthenticationPrincipal Jwt jwt, HttpServletRequest request) {
        String resourceServer = "https://localhost:8443";
        Map<String, Object> body = new HashMap<>();
        body.put("status", "success");
        body.put("endpoint", "/whereami");
        body.put("requiredScope", "(none — authentication only)");
        body.put("resource_server", resourceServer);
        body.put("served_at", request.getRequestURL().toString());
        body.put("token_aud", jwt.getAudience());
        body.put("audience_bound", jwt.getAudience() != null && jwt.getAudience().contains(resourceServer));
        return body;
    }
}
