/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.token;

import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * An implementation of ResourceServerTokenServices that reaches out to a remote 'check token' end-point
 * to validate an OAuth2 access token and build an OAuth2Authentication object from it.
 *
 * @author Vidya Valmikinathan
 */
public class RemoteTokenServices implements ResourceServerTokenServices, InitializingBean {

    protected final Log logger = LogFactory.getLog(getClass());
    private RestOperations restTemplate = new RestTemplate();

    private String checkTokenEndpointUrl;
    private String clientId;
    private String clientSecret;
    private String basicAuthHeader;

    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
        this.checkTokenEndpointUrl = checkTokenEndpointUrl;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void afterPropertiesSet() {
        Assert.state(clientId != null && clientSecret != null, "Supply client credentials to use with check_token endpoint");
        Assert.state(checkTokenEndpointUrl != null, "Supply an end-point to use for validating Oauth2 token");
        basicAuthHeader = getAuthorizationHeader(clientId, clientSecret);
    }

    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {

        Map<String, Object> validatedToken = validateToken(accessToken);
        logger.debug("Token contents: " + validatedToken);

        if (validatedToken.containsKey("error")) {
            logger.debug("check_token returned error: " + validatedToken.get("error"));
            throw new InvalidTokenException(accessToken);
        }

        return new OAuth2Authentication(buildClientAuth (validatedToken), buildUserAuth(validatedToken));
    }

    protected AuthorizationRequest buildClientAuth (Map<String, Object> token) {

        Assert.state(token.containsKey("client_id") && token.containsKey("aud") && token.containsKey("scope"), "A valid token should have client_id, aud and scope fields");

        String remoteClientId = (String) token.get("client_id");
        Set<String> scope = new HashSet<String>();
        if (token.containsKey("scope")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) token.get("scope");
            scope.addAll(values);
        }
        DefaultAuthorizationRequest clientAuth = new DefaultAuthorizationRequest(remoteClientId, scope);

        Set<String> resourceIds = new HashSet<String>();
        if (token.containsKey("aud")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) token.get("aud");
            resourceIds.addAll(values);
        }

        Set<GrantedAuthority> clientAuthorities = new HashSet<GrantedAuthority>();
        if (token.containsKey("client_authorities")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) token.get("client_authorities");
            clientAuthorities.addAll(getAuthorities(values));
        }
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(remoteClientId);
        clientDetails.setResourceIds(resourceIds);
        clientDetails.setAuthorities(clientAuthorities);
        clientAuth.addClientDetails(clientDetails);
        clientAuth.setApproved(true);
        return clientAuth;
    }

    protected Authentication buildUserAuth (Map<String, Object> token) {
        Assert.state(token.containsKey("scope"), "Invalid token: missing scope field");
        Set<String> scope = new HashSet<String>();
        if (token.containsKey("scope")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) token.get("scope");
            scope.addAll(values);
        }
        Set<GrantedAuthority> userAuthorities = new HashSet<GrantedAuthority>();
        if (token.containsKey("user_authorities")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) token.get("user_authorities");
            userAuthorities.addAll(getAuthorities(values));
        }
        else {
            // User authorities had better not be empty or we might mistake user for unauthenticated
            userAuthorities.addAll(getAuthorities(scope));
        }
        String username = (String) token.get("user_name");
        return new UsernamePasswordAuthenticationToken(username, null, userAuthorities);
    }

    public OAuth2AccessToken readAccessToken(String accessToken) {
        throw new UnsupportedOperationException("Not supported: read access token");
    }

    protected Map<String, Object> validateToken(String accessToken) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("token", accessToken);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", basicAuthHeader);
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        @SuppressWarnings("rawtypes")
        Map map = restTemplate.exchange(checkTokenEndpointUrl, HttpMethod.POST,
                new HttpEntity<MultiValueMap<String, String>>(formData, headers), Map.class).getBody();
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) map;
        return result;
    }

    private String getAuthorizationHeader(String clientId, String clientSecret) {
        try {
            return "Basic " +
                    new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes("UTF-8")));
        }
        catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Could not create Authorization header");
        }
    }

    private Set<GrantedAuthority> getAuthorities(Collection<String> authorities) {
        Set<GrantedAuthority> result = new HashSet<GrantedAuthority>();
        for (String authority : authorities) {
            result.add(new SimpleGrantedAuthority(authority));
        }
        return result;
    }

}
