/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.provider.client;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * A filter and authentication endpoint for the OAuth2 Token Endpoint. Allows clients to authenticate using request
 * parameters if included as a security filter, as permitted by the specification (but not recommended). It is
 * recommended by the specification that you permit HTTP basic authentication for clients, and not use this filter at
 * all.
 *
 * @author Dave Syer
 */
public class ClientCredentialsTokenEndpointFilter extends AbstractAuthenticationProcessingFilter {

    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    private boolean allowOnlyPost = false;

    public ClientCredentialsTokenEndpointFilter() {
        this("/oauth/token");
    }

    public ClientCredentialsTokenEndpointFilter(String path) {
        super(path);
        setRequiresAuthenticationRequestMatcher(new ClientCredentialsRequestMatcher(path));
        // If authentication fails the type is "Form"
        ((OAuth2AuthenticationEntryPoint) authenticationEntryPoint).setTypeName("Form");
    }

    public void setAllowOnlyPost(boolean allowOnlyPost) {
        this.allowOnlyPost = allowOnlyPost;
    }

    /**
     * @param authenticationEntryPoint the authentication entry point to set
     */
    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet();
        setAuthenticationFailureHandler(new AuthenticationFailureHandler() {
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationException exception) throws IOException, ServletException {
                if (exception instanceof BadCredentialsException) {
                    exception = new BadCredentialsException(exception.getMessage(), new BadClientCredentialsException());
                }
                authenticationEntryPoint.commence(request, response, exception);
            }
        });
        setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                Authentication authentication) throws IOException, ServletException {
                // no-op - just allow filter chain to continue to token endpoint
            }
        });
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        if (allowOnlyPost && !"POST".equalsIgnoreCase(request.getMethod())) {
            throw new HttpRequestMethodNotSupportedException(request.getMethod(), new String[]{"POST"});
        }

        String clientId = request.getParameter("client_id");
        String clientSecret = request.getParameter("client_secret");

        // If the request is already authenticated we can assume that this
        // filter is not needed
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return authentication;
        }

        if (clientId == null) {
            throw new BadCredentialsException("No client credentials presented");
        }

        if (StringUtils.isEmpty(clientSecret)) {
            clientSecret = "";
            String header = request.getHeader("Authorization");
            if (header != null && header.toLowerCase().startsWith("basic ")) {
                String[] tokens = extractAndDecodeHeader(header, request);
                if (tokens.length == 2) {
                    clientSecret = tokens[1];
                }
            }
        }

        clientId = clientId.trim();
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(clientId,
                clientSecret);

        return this.getAuthenticationManager().authenticate(authRequest);

    }

    /**
     * Decodes the header into a username and password.
     *
     * @throws BadCredentialsException if the Basic header is not present or is not valid
     *                                 Base64
     */
    private String[] extractAndDecodeHeader(String header, HttpServletRequest request)
            throws IOException {

        byte[] base64Token = header.substring(6).getBytes("UTF-8");
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64Token);
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException(
                    "Failed to decode basic authentication token");
        }

        String token = new String(decoded, StandardCharsets.UTF_8);

        int delim = token.indexOf(":");

        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return new String[]{token.substring(0, delim), token.substring(delim + 1)};
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);
    }

    protected static class ClientCredentialsRequestMatcher implements RequestMatcher {

        private String path;

        public ClientCredentialsRequestMatcher(String path) {
            this.path = path;

        }

        @Override
        public boolean matches(HttpServletRequest request) {
            String uri = request.getRequestURI();
            int pathParamIndex = uri.indexOf(';');

            if (pathParamIndex > 0) {
                // strip everything after the first semi-colon
                uri = uri.substring(0, pathParamIndex);
            }

            String clientId = request.getParameter("client_id");

            if (clientId == null) {
                // Give basic auth a chance to work instead (it's preferred anyway)
                return false;
            }

            if ("".equals(request.getContextPath())) {
                return uri.endsWith(path);
            }

            return uri.endsWith(request.getContextPath() + path);
        }

    }

}
