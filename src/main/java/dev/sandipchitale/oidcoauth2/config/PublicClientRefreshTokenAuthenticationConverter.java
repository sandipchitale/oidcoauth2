package dev.sandipchitale.oidcoauth2.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!OAuth2ParameterNames.REFRESH_TOKEN.equals(grantType)) {
            return null;
        }

        // Public clients do not use client secrets or basic auth
        String header = request.getHeader("Authorization");
        String clientSecret = request.getParameter("client_secret");
        if (StringUtils.hasText(header) || StringUtils.hasText(clientSecret)) {
            return null;
        }

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        request.getParameterMap().forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.CLIENT_ID) &&
                    !key.equals(OAuth2ParameterNames.CLIENT_SECRET)) {
                additionalParameters.put(key, (value.length == 1) ? value[0] : value);
            }
        });

        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null, additionalParameters);
    }
}
