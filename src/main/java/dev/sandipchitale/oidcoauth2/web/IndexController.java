package dev.sandipchitale.oidcoauth2.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class IndexController {

    @GetMapping("/")
    public void index(HttpServletResponse response) throws IOException {
        response.sendRedirect("/client.html");
    }

    // RFC 9728 Protected Resource Metadata (/.well-known/oauth-protected-resource) is now served
    // declaratively by OAuth2ProtectedResourceMetadataFilter, configured via
    // oauth2ResourceServer().protectedResourceMetadata(...) in SecurityConfig.
}
