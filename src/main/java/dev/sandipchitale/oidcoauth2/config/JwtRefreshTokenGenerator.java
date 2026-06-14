package dev.sandipchitale.oidcoauth2.config;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import java.time.Instant;
import java.util.Collections;
import java.util.UUID;

public class JwtRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private final JwtEncoder jwtEncoder;

    public JwtRefreshTokenGenerator(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @Nullable
    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.getValue().equals(context.getTokenType().getValue())) {
            return null;
        }

        // We only generate a refresh token if refresh_token grant type is supported or allowed
        if (!context.getAuthorizedScopes().isEmpty() &&
                !context.getRegisteredClient().getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            return null;
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());

        String issuer = null;
        context.getAuthorizationServerContext();
        issuer = context.getAuthorizationServerContext().getIssuer();

        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(context.getPrincipal().getName())
                .audience(Collections.singletonList(context.getRegisteredClient().getClientId()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim("token_type", "refresh_token");

        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
        Jwt jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsBuilder.build()));

        return new OAuth2RefreshToken(jwt.getTokenValue(), issuedAt, expiresAt);
    }
}
