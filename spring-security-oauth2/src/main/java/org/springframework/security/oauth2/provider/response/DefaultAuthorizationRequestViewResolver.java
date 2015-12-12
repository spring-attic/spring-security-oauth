package org.springframework.security.oauth2.provider.response;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Default AuthorizationRequestViewResolver
 *
 * @author Okke Harsta
 */
public class DefaultAuthorizationRequestViewResolver implements AuthorizationRequestViewResolver {

    @Override
    public View getSuccessfulAuthorizationCodeView(AuthorizationRequest authorizationRequest,
                                                   String authorizationCode) {
        if (authorizationCode == null) {
            throw new IllegalStateException("No authorization code found in the current request scope.");
        }

        Map<String, String> query = new LinkedHashMap<String, String>();
        query.put("code", authorizationCode);

        String state = authorizationRequest.getState();
        if (state != null) {
            query.put("state", state);
        }

        return new RedirectView(append(authorizationRequest.getRedirectUri(), query, false), false, true, false);
    }

    @Override
    public View getSuccessfulImplicitGrantView(AuthorizationRequest authorizationRequest,
                                               OAuth2AccessToken accessToken) {
        return new RedirectView(appendAccessToken(authorizationRequest, accessToken), false, true,
                false);
    }

    public View getUnsuccessfulView(AuthorizationRequest authorizationRequest, OAuth2Exception failure) {

        if (authorizationRequest == null || authorizationRequest.getRedirectUri() == null) {
            // we have no redirect for the user. very sad.
            throw new UnapprovedClientAuthenticationException("Authorization failure, and no redirect URI.", failure);
        }

        Map<String, String> query = new LinkedHashMap<String, String>();

        query.put("error", failure.getOAuth2ErrorCode());
        query.put("error_description", failure.getMessage());

        if (authorizationRequest.getState() != null) {
            query.put("state", authorizationRequest.getState());
        }

        if (failure.getAdditionalInformation() != null) {
            for (Map.Entry<String, String> additionalInfo : failure.getAdditionalInformation().entrySet()) {
                query.put(additionalInfo.getKey(), additionalInfo.getValue());
            }
        }

        String url = append(authorizationRequest.getRedirectUri(), query, appendToFragment(authorizationRequest));
        return new RedirectView(url, false, true, false);

    }

    protected boolean appendToFragment(AuthorizationRequest authorizationRequest) {
        return authorizationRequest.getResponseTypes().contains("token");
    }

    private String append(String base, Map<String, ?> query, boolean fragment) {
        return append(base, query, null, fragment);
    }

    private String append(String base, Map<String, ?> query, Map<String, String> keys, boolean fragment) {

        UriComponentsBuilder template = UriComponentsBuilder.newInstance();
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(base);
        URI redirectUri;
        try {
            // assume it's encoded to start with (if it came in over the wire)
            redirectUri = builder.build(true).toUri();
        }
        catch (Exception e) {
            // ... but allow client registrations to contain hard-coded non-encoded values
            redirectUri = builder.build().toUri();
            builder = UriComponentsBuilder.fromUri(redirectUri);
        }
        template.scheme(redirectUri.getScheme()).port(redirectUri.getPort()).host(redirectUri.getHost())
                .userInfo(redirectUri.getUserInfo()).path(redirectUri.getPath());

        if (fragment) {
            StringBuilder values = new StringBuilder();
            if (redirectUri.getFragment() != null) {
                String append = redirectUri.getFragment();
                values.append(append);
            }
            for (String key : query.keySet()) {
                if (values.length() > 0) {
                    values.append("&");
                }
                String name = key;
                if (keys != null && keys.containsKey(key)) {
                    name = keys.get(key);
                }
                values.append(name + "={" + key + "}");
            }
            if (values.length() > 0) {
                template.fragment(values.toString());
            }
            UriComponents encoded = template.build().expand(query).encode();
            builder.fragment(encoded.getFragment());
        }
        else {
            for (String key : query.keySet()) {
                String name = key;
                if (keys != null && keys.containsKey(key)) {
                    name = keys.get(key);
                }
                template.queryParam(name, "{" + key + "}");
            }
            template.fragment(redirectUri.getFragment());
            UriComponents encoded = template.build().expand(query).encode();
            builder.query(encoded.getQuery());
        }

        return builder.build().toUriString();

    }

    private String appendAccessToken(AuthorizationRequest authorizationRequest, OAuth2AccessToken accessToken) {

        Map<String, Object> vars = new LinkedHashMap<String, Object>();
        Map<String, String> keys = new HashMap<String, String>();

        if (accessToken == null) {
            throw new InvalidRequestException("An implicit grant could not be made");
        }

        vars.put("access_token", accessToken.getValue());
        vars.put("token_type", accessToken.getTokenType());
        String state = authorizationRequest.getState();

        if (state != null) {
            vars.put("state", state);
        }
        Date expiration = accessToken.getExpiration();
        if (expiration != null) {
            long expires_in = (expiration.getTime() - System.currentTimeMillis()) / 1000;
            vars.put("expires_in", expires_in);
        }
        String originalScope = authorizationRequest.getRequestParameters().get(OAuth2Utils.SCOPE);
        if (originalScope == null || !OAuth2Utils.parseParameterList(originalScope).equals(accessToken.getScope())) {
            vars.put("scope", OAuth2Utils.formatParameterList(accessToken.getScope()));
        }
        Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
        for (String key : additionalInformation.keySet()) {
            Object value = additionalInformation.get(key);
            if (value != null) {
                keys.put("extra_" + key, key);
                vars.put("extra_" + key, value);
            }
        }
        // Do not include the refresh token (even if there is one)
        return append(authorizationRequest.getRedirectUri(), vars, keys, true);
    }



}
