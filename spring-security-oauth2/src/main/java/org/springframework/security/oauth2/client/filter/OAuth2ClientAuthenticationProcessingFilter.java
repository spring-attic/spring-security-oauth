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

package org.springframework.security.oauth2.client.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.token.auth.CheckTokenServices;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;

/**
 * An OAuth2 client filter that can be used to acquire an OAuth2 access token from an authorization server,
 * and load an authentication object into the SecurityContext
 *
 * @author Vidya Valmikinathan
 *
 */
public class OAuth2ClientAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    public RestOperations restTemplate;

    private String userInfoUrl;

    private CheckTokenServices tokenServices;

    /**
     * Reference to a CheckTokenServices that can validate an OAuth2AccessToken
     *
     * @param tokenServices
     */
    public void setTokenServices(CheckTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    /**
     * A rest template to be used to contact the remote user info endpoint. Normally would be an instance of
     * {@link OAuth2RestTemplate}, but there is no need for that dependency to be explicit, and there are advantages in
     * making it implicit (e.g. for testing purposes).
     *
     * @param restTemplate a rest template
     */
    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * The URL of a resource on the remote Authorization Server which provides user profile data.
     * Can be used to optionally augment the data available in the OAuth2 token.
     *
     * @param userInfoUrl
     */
    public void setUserInfoUrl(String userInfoUrl) {
        this.userInfoUrl = userInfoUrl;
    }

    public OAuth2ClientAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
        setAuthenticationManager(new OAuth2AuthenticationManager());
    }

    @Override
    public void afterPropertiesSet() {
        Assert.state(restTemplate != null, "Supply a rest-template");
        super.afterPropertiesSet();
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        Map<String, String> userInfo = null;
        if (userInfoUrl != null) {
            try {
                userInfo = restTemplate.getForObject(userInfoUrl, Map.class);
            } catch (RestClientException ex) {
                userInfo = Collections.emptyMap();
            }
        }

        if (restTemplate instanceof OAuth2RestTemplate) {
            OAuth2RestTemplate oauth2RestTemplate = ((OAuth2RestTemplate) restTemplate);
            OAuth2AccessToken accessToken = oauth2RestTemplate.getAccessToken();
            return tokenServices.loadAuthentication(accessToken, userInfo);
        } else {
            String username = getUserName(userInfo);
            String id = getUserId(userInfo);
            AnonymousAuthenticationToken unknownUser = new AnonymousAuthenticationToken(id, username, AuthorityUtils.NO_AUTHORITIES);
            unknownUser.setAuthenticated(false);
            return unknownUser;
        }

    }

    protected String getUserId(Map<String, String> userInfo) {
        String id = userInfo.get("id");
        if (!StringUtils.hasText(id)) {
            id = userInfo.get("user_id");
        }
        return id;
    }

    protected String getUserName(Map<String, String> userInfo) {
        List<String> options = Arrays.asList("username", "user_name", "login", "screen_name", "email");
        String username = "";
        for (String key : options) {
            username = userInfo.get(key);
            if (StringUtils.hasText(username)) {
                return username;
            }
        }
        return getUserId(userInfo);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        if (failed instanceof AccessTokenRequiredException) {
            // Need to force a redirect via the OAuth client filter, so rethrow here
            throw failed;
        }
        else {
            // If the exception is not a Spring Security exception this will result in a default error page
            super.unsuccessfulAuthentication(request, response, failed);
        }
    }

}