package dev.sandipchitale.oidcoauth2.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A deliberately minimal RFC 7591 (OAuth 2.0 Dynamic Client Registration) endpoint.
 *
 * <p>This is <b>not</b> a general-purpose registrar: it does not mint new clients. It exists only so the
 * stateless SPA can <i>discover</i> its {@code client_id} at runtime instead of hard-coding it. The single
 * well-known client of this demo is named {@value #WELL_KNOWN_CLIENT_NAME} but its {@code client_id} is an
 * opaque UUID the client could not guess; a registration request for that {@code client_name} echoes back
 * the pre-registered client's metadata (an RFC 7591 Client Information Response), including that UUID
 * {@code client_id}. Any other {@code client_name} is rejected with an {@code invalid_client_metadata} error.
 *
 * <p>The endpoint is advertised as {@code registration_endpoint} in both the RFC 8414 authorization server
 * metadata and the OIDC provider configuration (see {@code SecurityConfig}), so the client finds it through
 * normal discovery.
 */
@RestController
public class ClientRegistrationController {

    /** The one client name this demo will "register" — it maps to the pre-registered public client. */
    public static final String WELL_KNOWN_CLIENT_NAME = "client";

    private final RegisteredClient client;

    public ClientRegistrationController(RegisteredClient oidcClient) {
        this.client = oidcClient;
    }

    @PostMapping(value = "/connect/register",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, Object> registrationRequest) {
        Object clientName = registrationRequest.get("client_name");

        // Match on client_name (not client_id) — the client_id is an opaque UUID the caller cannot know;
        // discovering it is the whole point. Only the well-known name maps to our pre-registered client.
        if (!WELL_KNOWN_CLIENT_NAME.equals(clientName) || !WELL_KNOWN_CLIENT_NAME.equals(client.getClientName())) {
            // RFC 7591 §3.2.2 error response — only the well-known client may be "registered" here.
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_client_metadata",
                    "error_description", "This authorization server only registers the well-known client named \""
                            + WELL_KNOWN_CLIENT_NAME + "\"."));
        }

        // RFC 7591 §3.2.1 Client Information Response describing the (pre-)registered client.
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("client_id", client.getClientId());
        response.put("client_name", client.getClientName());
        response.put("redirect_uris", new ArrayList<>(client.getRedirectUris()));
        response.put("grant_types", client.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue).toList());
        response.put("response_types", List.of("code"));
        response.put("token_endpoint_auth_method", client.getClientAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::getValue).findFirst().orElse("none"));
        response.put("scope", String.join(" ", client.getScopes()));
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
