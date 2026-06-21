package dev.sandipchitale.oidcoauth2.config;

import jakarta.servlet.http.HttpServletResponse;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadataClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // The OpenID Provider's own identifier (issuer). An 'openid' access token is consumed at this OP's
    // UserInfo endpoint, so the OP is its (unambiguous) audience even without a resource indicator.
    private static final String OP_AUDIENCE = "https://localhost.apple.com:8443";
    // The resource server's canonical URI (reached at localhost). A token is accepted at /get,/post only
    // if its 'aud' contains this value, which happens only when the client sent it as a resource indicator.
    private static final String RS_AUDIENCE = "https://localhost:8443";
    // Our custom RFC 7591 Dynamic Client Registration endpoint (served by ClientRegistrationController),
    // advertised as 'registration_endpoint' in the AS/OIDC metadata so the SPA can discover its client_id.
    private static final String REGISTRATION_ENDPOINT = OP_AUDIENCE + "/connect/register";

    @Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http, RegisteredClientRepository registeredClientRepository, JWKSource<SecurityContext> jwkSource) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = getOAuth2AuthorizationServerConfigurer(registeredClientRepository);

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http
                .securityMatcher(endpointsMatcher)
                // Require an authenticated resource owner for the authorization server endpoints. Without
                // this, an anonymous /oauth2/authorize request is never redirected to the login page; it
                // falls straight through to the authorization endpoint, which fails with
                // "[invalid_request] OAuth 2.0 Parameter: principal".
                .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                // The OAuth2 endpoints (e.g. the token endpoint POSTed by the stateless SPA) are not
                // browser-form submissions and carry no CSRF token, so exclude them from CSRF protection.
                .csrf((csrf) -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .with(authorizationServerConfigurer, (authorizationServer) -> {
                    authorizationServer.oidc(oidc -> oidc
                            // Standard OIDC UserInfo: always returns 'sub', plus profile claims when the
                            // 'profile' scope was granted. Access is gated by the 'openid' scope.
                            .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(SecurityConfig::userInfo))
                            // Advertise our custom RFC 7591 registration endpoint in the OIDC provider
                            // configuration (/.well-known/openid-configuration) as 'registration_endpoint'.
                            .providerConfigurationEndpoint(providerConfiguration -> providerConfiguration
                                    .providerConfigurationCustomizer(builder -> builder
                                            .clientRegistrationEndpoint(REGISTRATION_ENDPOINT)))
                    ); // Enable OpenID Connect 1.0
                    // Advertise the same 'registration_endpoint' in the RFC 8414 authorization server
                    // metadata (/.well-known/oauth-authorization-server).
                    authorizationServer.authorizationServerMetadataEndpoint(metadata -> metadata
                            .authorizationServerMetadataCustomizer(builder -> builder
                                    .clientRegistrationEndpoint(REGISTRATION_ENDPOINT)));
                })
                // Redirect to the login page when not authenticated from the authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // UserInfo accepts an access token only if its 'aud' includes the OP audience (stamped in
                // whenever the 'openid' scope is granted). This is the "door check" for the OP resource.
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(jwt -> jwt.decoder(audienceValidatingJwtDecoder(jwkSource, OP_AUDIENCE))))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        return http.build();
    }

    /**
     * A JWT decoder that, on top of signature/timestamp validation, requires the token's {@code aud} claim
     * to contain {@code requiredAudience}. A token whose audience does not include this resource is rejected
     * with {@code 401 invalid_token} before any scope check — this is audience validation (RFC 9068 / OAuth
     * 2.1 §5.2): "is this token meant for me?"
     */
    private static JwtDecoder audienceValidatingJwtDecoder(JWKSource<SecurityContext> jwkSource, String requiredAudience) {
        NimbusJwtDecoder decoder = (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD,
                (aud) -> aud != null && aud.contains(requiredAudience));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefault(), audienceValidator));
        return decoder;
    }

    private static @NonNull OAuth2AuthorizationServerConfigurer getOAuth2AuthorizationServerConfigurer(RegisteredClientRepository registeredClientRepository) {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        authorizationServerConfigurer
                .clientAuthentication(clientAuthentication -> clientAuthentication
                        .authenticationConverters(converters -> converters.add(new PublicClientRefreshTokenAuthenticationConverter()))
                        .authenticationProviders(providers -> providers.add(new PublicClientRefreshTokenAuthenticationProvider(registeredClientRepository)))
                );
        return authorizationServerConfigurer;
    }

    /**
     * Standard OIDC UserInfo claims mapper. The {@code sub} claim is always returned; the standard
     * {@code profile}-scope claims are added only when the {@code profile} scope was granted (per
     * OpenID Connect Core 5.4). Access to the endpoint itself is gated by the {@code openid} scope.
     */
    private static OidcUserInfo userInfo(OidcUserInfoAuthenticationContext context) {
        OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
        JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
        String username = principal.getName();

        Set<String> scopes = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("SCOPE_"))
                .map(a -> a.substring("SCOPE_".length()))
                .collect(java.util.stream.Collectors.toSet());

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", username);
        if (scopes.contains("profile")) {
            claims.put("name", username);
            claims.put("preferred_username", username);
            claims.put("updated_at", Instant.now().getEpochSecond());
        }
        if (scopes.contains("email")) {
            claims.put("email", username + "@example.com");
            claims.put("email_verified", true);
        }
        return new OidcUserInfo(claims);
    }

    @Bean
    @Order(2)
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http, JWKSource<SecurityContext> jwkSource) throws Exception {
        http
                .securityMatcher("/get", "/post", "/whoami", "/whereami", "/.well-known/oauth-protected-resource")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, "/get").hasAuthority("SCOPE_READ")
                        .requestMatchers(HttpMethod.POST, "/post").hasAuthority("SCOPE_WRITE")
                        // RFC 9728 protected resource metadata is public discovery — served by the
                        // OAuth2ProtectedResourceMetadataFilter below, no token required.
                        .requestMatchers(HttpMethod.GET, "/.well-known/oauth-protected-resource").permitAll()
                        // /whoami and /whereami require only a valid, audience-bound token — no scope.
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        // Door check: accept a token only if its 'aud' includes this resource server, then
                        // authorize the operation by scope. A token not minted for this RS (no resource
                        // indicator) is rejected with 401 before the scope check even runs.
                        .jwt(jwt -> jwt.decoder(audienceValidatingJwtDecoder(jwkSource, RS_AUDIENCE)))
                        // RFC 9728 Protected Resource Metadata at /.well-known/oauth-protected-resource.
                        // OAuth2ProtectedResourceMetadataFilter pre-seeds: resource (from the request URL),
                        // bearer_methods_supported=["header"], tls_client_certificate_bound_access_tokens=true.
                        // We pin resource to this RS's canonical URI, advertise the AS and this RS's own
                        // scopes, and drop the mTLS claim since this RS issues no certificate-bound tokens.
                        .protectedResourceMetadata(metadata -> metadata
                                .protectedResourceMetadataCustomizer(builder -> builder
                                        .resource(RS_AUDIENCE)
                                        .authorizationServer(OP_AUDIENCE)
                                        .scope("READ")
                                        .scope("WRITE")
                                        .claims(claims -> claims.remove(
                                                OAuth2ProtectedResourceMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS))))
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            String requiredScope = request.getRequestURI().equals("/get") ? "READ" : "WRITE";
                            // Per the MCP "Scope Challenge Handling" spec (Recommended approach): include the
                            // scopes already granted to the current token alongside the newly-required scope,
                            // so the client does not lose previously granted permissions when it performs the
                            // step-up (re-)authorization flow.
                            String challengeScope = buildChallengeScope(requiredScope);
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.setHeader("WWW-Authenticate",
                                    "Bearer error=\"insufficient_scope\", " +
                                    "scope=\"" + challengeScope + "\", " +
                                    "resource_metadata=\"https://localhost:8443/.well-known/oauth-protected-resource\", " +
                                    "error_description=\"The access token lacks the required scope: " + requiredScope + "\"");
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\": \"insufficient_scope\", \"scope\": \"" + challengeScope + "\"}");
                        })
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.setHeader("WWW-Authenticate",
                                    "Bearer error=\"invalid_token\", " +
                                    "resource_metadata=\"https://localhost:8443/.well-known/oauth-protected-resource\", " +
                                    "error_description=\"The access token is invalid, missing, or expired.\"");
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\": \"invalid_token\"}");
                        })
                )
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable()); // Disable CSRF for REST resource server endpoints

        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        // /connect/register is the public RFC 7591 Dynamic Client Registration endpoint.
                        .requestMatchers("/", "/client.html", "/connect/register").permitAll()
                        .anyRequest().authenticated()
                )
                // The registration endpoint is a cross-origin JSON POST from the SPA carrying no CSRF token.
                .csrf(csrf -> csrf.ignoringRequestMatchers("/connect/register"))
                // Form login handles the redirect from the authorization server filter chain
                .formLogin(Customizer.withDefaults())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        return http.build();
    }

    /**
     * Builds the {@code scope} value advertised in an {@code insufficient_scope} challenge, following
     * the MCP "Scope Challenge Handling" Recommended approach: union of the scopes already granted to
     * the current access token and the newly-required scope. Returning the union prevents the client
     * from dropping previously granted permissions during the step-up authorization flow.
     */
    private static String buildChallengeScope(String requiredScope) {
        Set<String> scopes = new LinkedHashSet<>();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            for (GrantedAuthority authority : authentication.getAuthorities()) {
                String value = authority.getAuthority();
                if (value.startsWith("SCOPE_")) {
                    scopes.add(value.substring("SCOPE_".length()));
                }
            }
        }
        scopes.add(requiredScope);
        return String.join(" ", scopes);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withUsername("user")
                .password("{noop}password")
                .roles("USER")
                .build();
        UserDetails userDetails2 = User.withUsername("user2")
                .password("{noop}password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails, userDetails2);
    }

    @Bean
    public RegisteredClient oidcClient(@Value("${app.client-id}") String clientId) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                // Configured (durable) opaque client_id — stable across restarts so previously issued
                // tokens stay valid. The SPA never hard-codes it; it learns it at runtime by sending its
                // client_name ("client") to the RFC 7591 registration endpoint (see DCR controller).
                .clientId(clientId)
                .clientName("client") // matched by the RFC 7591 registration endpoint (client_name)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Public client (no client secret)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://localhost.apple.com:8443/client.html")
                .redirectUri("https://localhost.apple.com:8443/")
                .redirectUri("https://localhost:8443/client.html")
                .redirectUri("https://localhost:8443/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope(OidcScopes.ADDRESS)
                .scope(OidcScopes.PHONE)
                .scope("READ")
                .scope("WRITE")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true) // Enforce PKCE
                        .requireAuthorizationConsent(true) // Show consent screen to support scope changes
                        .build())
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(RegisteredClient oidcClient) {
        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder, OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        JwtRefreshTokenGenerator refreshTokenGenerator = new JwtRefreshTokenGenerator(jwtEncoder);
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
    }

    /**
     * Sets the access token's {@code aud} (audience) claim to its actual consumer(s):
     * <ul>
     *   <li>the resource server(s) named by the RFC 8707 {@code resource} indicator, and</li>
     *   <li>the OP itself when the {@code openid} scope is present (the token is consumed at its UserInfo
     *       endpoint — an unambiguous audience that needs no resource indicator).</li>
     * </ul>
     * If neither applies, the {@code aud} claim is <b>removed</b> rather than left as SAS's default of the
     * {@code client_id}: the client is the token's bearer, not its consumer, so it is never an audience.
     * Scopes are never used to infer a resource-server audience (a {@code READ}/{@code WRITE} scope does
     * not identify <i>which</i> resource server). The ID token is untouched ({@code aud=client_id}, per OIDC).
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Set<String> audiences = new LinkedHashSet<>(requestedResourceIndicators(context));
                if (context.getAuthorizedScopes().contains(OidcScopes.OPENID)) {
                    audiences.add(OP_AUDIENCE);
                }
                if (audiences.isEmpty()) {
                    context.getClaims().claims(claims -> claims.remove("aud"));
                } else {
                    context.getClaims().audience(new ArrayList<>(audiences));
                }
            }
        };
    }

    /**
     * Extracts the RFC 8707 {@code resource} indicator(s) from the current grant (token / refresh request).
     * SAS does not process {@code resource} natively, so non-standard request parameters are carried in the
     * grant's additional parameters.
     */
    private static List<String> requestedResourceIndicators(JwtEncodingContext context) {
        List<String> resources = new ArrayList<>();
        if (context.getAuthorizationGrant() instanceof OAuth2AuthorizationGrantAuthenticationToken grant) {
            Object value = grant.getAdditionalParameters().get("resource");
            if (value instanceof String s) {
                if (!s.isBlank()) {
                    resources.add(s);
                }
            } else if (value instanceof List<?> list) {
                for (Object item : list) {
                    if (item != null && !item.toString().isBlank()) {
                        resources.add(item.toString());
                    }
                }
            }
        }
        return resources;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("https://localhost.apple.com:8443")
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Collections.singletonList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
