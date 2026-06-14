package dev.sandipchitale.oidcoauth2.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@RestController
public class MetadataController {

    @GetMapping("/")
    public void index(HttpServletResponse response) throws IOException {
        response.sendRedirect("/client.html");
    }

    @GetMapping("/.well-known/oauth-protected-resource")
    public Map<String, Object> getProtectedResourceMetadata() {
        return Map.of(
                // The resource server is reached at localhost; its canonical URI is the access token audience.
                "resource", "https://localhost:8443",
                // The authorization server lives on localhost.apple.com.
                "authorization_servers", List.of("https://localhost.apple.com:8443"),
                // RFC 9728: only THIS resource server's own scopes belong here. The OIDC scopes
                // (openid, profile, email, ...) are the OP's and are advertised by the OP's metadata
                // (/.well-known/openid-configuration), not by the resource server.
                "scopes_supported", List.of("READ", "WRITE"),
                "bearer_methods_supported", List.of("header")
        );
    }
}
