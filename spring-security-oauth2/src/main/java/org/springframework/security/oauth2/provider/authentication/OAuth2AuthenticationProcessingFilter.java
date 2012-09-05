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
package org.springframework.security.oauth2.provider.authentication;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;

/**
 * A pre-authemtication filter for OAuth2 protected resources. Extracts an OAuth2 token from the in coming request and
 * uses it to populate the Spring Security context with an {@link OAuth2Authentication} (if used in conjunction with an
 * {@link OAuth2AuthenticationManager}).
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2AuthenticationProcessingFilter implements Filter, InitializingBean {

	private final static Log logger = LogFactory.getLog(OAuth2AuthenticationProcessingFilter.class);

	private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

	private AuthenticationManager authenticationManager;

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new OAuth2AuthenticationDetailsSource();

    private RestOperations restTemplate;

    /**
     * A rest template to be used to contact a remote token endpoint to acquire an OAuth2 access token. Normally would be an instance of
     * {@link OAuth2RestTemplate}, but there is no need for that dependency to be explicit, and there are advantages in
     * making it implicit (e.g. for testing purposes).
     *
     * @param restTemplate a rest template
     */
    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
	 * @param authenticationEntryPoint the authentication entry point to set
	 */
	public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	/**
	 * @param authenticationManager the authentication manager to set (mandatory with no default)
	 */
	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

    /**
     * @param authenticationDetailsSource
     *            The AuthenticationDetailsSource to use
     */
    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest,?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

	public void afterPropertiesSet() {
		Assert.state(authenticationManager != null, "AuthenticationManager is required");
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
			ServletException {

		final boolean debug = logger.isDebugEnabled();
		final HttpServletRequest request = (HttpServletRequest) req;
		final HttpServletResponse response = (HttpServletResponse) res;

		try {

			String tokenValue = parseToken(request);
			if (tokenValue == null) {
				if (debug) {
					logger.debug("No token in request, will continue chain.");
				}
			}
			else {
				PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(
						tokenValue, "");
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, tokenValue);
				authentication.setDetails(authenticationDetailsSource.buildDetails(request));
				Authentication authResult = authenticationManager.authenticate(authentication);

				if (debug) {
					logger.debug("Authentication success: " + authResult);
				}

				SecurityContextHolder.getContext().setAuthentication(authResult);

			}
		}
		catch (OAuth2Exception failed) {
			SecurityContextHolder.clearContext();

			if (debug) {
				logger.debug("Authentication request failed: " + failed);
			}

			authenticationEntryPoint.commence(request, response,
					new InsufficientAuthenticationException(failed.getMessage(), failed));

			return;
		}

		chain.doFilter(request, response);
	}

	protected String parseToken(HttpServletRequest request) {
		// first check the header...
		String token = parseHeaderToken(request);

		// bearer type allows a request parameter as well
		if (token == null) {
			logger.debug("Token not found in headers. Trying request parameters.");
			token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
			}

        // If an OAuth2RestTemplate is wired in, use that to acquire a token
        if (token == null) {
            logger.debug("Token not found in request parameters.  Not an OAuth2 request.");
            if (restTemplate instanceof OAuth2RestTemplate) {
                logger.debug("Attempting to acquire an OAuth2 access token");
                token = ((OAuth2RestTemplate) restTemplate).getAccessToken().getValue();
            }
        }

        return token;
	}

	/**
	 * Parse the OAuth header parameters. The parameters will be oauth-decoded.
	 * 
	 * @param request The request.
	 * @return The parsed parameters, or null if no OAuth authorization header was supplied.
	 */
	protected String parseHeaderToken(HttpServletRequest request) {
		@SuppressWarnings("unchecked")
		Enumeration<String> headers = request.getHeaders("Authorization");
		while (headers.hasMoreElements()) { // typically there is only one (most servers enforce that)
			String value = headers.nextElement();
			if ((value.toLowerCase().startsWith(OAuth2AccessToken.BEARER_TYPE.toLowerCase()))) {
				String authHeaderValue = value.substring(OAuth2AccessToken.BEARER_TYPE.length()).trim();
				int commaIndex = authHeaderValue.indexOf(',');
				if (commaIndex > 0) {
					authHeaderValue = authHeaderValue.substring(0, commaIndex);
				}
				return authHeaderValue;
			}
			else {
				// todo: support additional authorization schemes for different token types, e.g. "MAC" specified by
				// http://tools.ietf.org/html/draft-hammer-oauth-v2-mac-token
			}
		}

		return null;
	}

	public void init(FilterConfig filterConfig) throws ServletException {
	}

	public void destroy() {
	}

}
