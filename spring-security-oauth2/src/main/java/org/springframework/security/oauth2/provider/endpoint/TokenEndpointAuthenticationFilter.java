/*
 * Copyright 2012-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.endpoint;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

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
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * <p>
 * An optional authentication filter for the {@link TokenEndpoint}. It sits downstream of another filter (usually
 * {@link BasicAuthenticationFilter}) for the client, and creates an {@link OAuth2Authentication} for the Spring
 * {@link SecurityContext} if the request also contains user credentials, e.g. as typically would be the case in a
 * password grant. This filter is only required if the TokenEndpoint (or one of it's dependencies) needs to know about
 * the authenticated user. In a vanilla password grant this <b>isn't</b> normally necessary because the token granter
 * will also authenticate the user.
 * </p>
 * 
 * <p>
 * If this filter is used the Spring Security context will contain an OAuth2Authentication encapsulating (as the
 * authorization request) the form parameters coming into the filter and the client id from the already authenticated
 * client authentication, and the authenticated user token extracted from the request and validated using the
 * authentication manager.
 * </p>
 * 
 * @author Dave Syer
 * 
 */
public class TokenEndpointAuthenticationFilter implements Filter {

	private static final Log logger = LogFactory.getLog(TokenEndpointAuthenticationFilter.class);

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

	private final AuthenticationManager authenticationManager;
	
	private final OAuth2RequestFactory oAuth2RequestFactory;

	/**
	 * @param authenticationManager an AuthenticationManager for the incoming request
	 */
	public TokenEndpointAuthenticationFilter(AuthenticationManager authenticationManager, OAuth2RequestFactory oAuth2RequestFactory) {
		super();
		this.authenticationManager = authenticationManager;
		this.oAuth2RequestFactory = oAuth2RequestFactory;
	}

	/**
	 * An authentication entry point that can handle unsuccessful authentication. Defaults to an
	 * {@link OAuth2AuthenticationEntryPoint}.
	 * 
	 * @param authenticationEntryPoint the authenticationEntryPoint to set
	 */
	public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	/**
	 * A source of authentication details for requests that result in authentication.
	 * 
	 * @param authenticationDetailsSource the authenticationDetailsSource to set
	 */
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
			ServletException {

		final boolean debug = logger.isDebugEnabled();
		final HttpServletRequest request = (HttpServletRequest) req;
		final HttpServletResponse response = (HttpServletResponse) res;

		try {
			Authentication credentials = extractCredentials(request);

			if (credentials != null) {

				if (debug) {
					logger.debug("Authentication credentials found for '" + credentials.getName() + "'");
				}

				Authentication authResult = authenticationManager.authenticate(credentials);

				if (debug) {
					logger.debug("Authentication success: " + authResult.getName());
				}

				Authentication clientAuth = SecurityContextHolder.getContext().getAuthentication();
				if (clientAuth == null) {
					throw new BadCredentialsException(
							"No client authentication found. Remember to put a filter upstream of the TokenEndpointAuthenticationFilter.");
				}
				
				Map<String, String> map = getSingleValueMap(request);
				map.put(OAuth2Utils.CLIENT_ID, clientAuth.getName());
				AuthorizationRequest authorizationRequest = oAuth2RequestFactory.createAuthorizationRequest(map);

				authorizationRequest.setScope(getScope(request));
				if (clientAuth.isAuthenticated()) {
					// Ensure the OAuth2Authentication is authenticated
					authorizationRequest.setApproved(true);
				}

				OAuth2Request storedOAuth2Request = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);
				
				SecurityContextHolder.getContext().setAuthentication(
						new OAuth2Authentication(storedOAuth2Request, authResult));

				onSuccessfulAuthentication(request, response, authResult);

			}

		}
		catch (AuthenticationException failed) {
			SecurityContextHolder.clearContext();

			if (debug) {
				logger.debug("Authentication request for failed: " + failed);
			}

			onUnsuccessfulAuthentication(request, response, failed);

			authenticationEntryPoint.commence(request, response, failed);

			return;
		}

		chain.doFilter(request, response);
	}

	private Map<String, String> getSingleValueMap(HttpServletRequest request) {
		Map<String, String> map = new HashMap<String, String>();
		Map<String, String[]> parameters = request.getParameterMap();
		for (String key : parameters.keySet()) {
			String[] values = parameters.get(key);
			map.put(key, values != null && values.length > 0 ? values[0] : null);
		}
		return map;
	}

	protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			Authentication authResult) throws IOException {
	}

	protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException {
	}

	/**
	 * If the incoming request contains user credentials in headers or parameters then extract them here into an
	 * Authentication token that can be validated later. This implementation only recognises password grant requests and
	 * extracts the username and password.
	 * 
	 * @param request the incoming request, possibly with user credentials
	 * @return an authentication for validation (or null if there is no further authentication)
	 */
	protected Authentication extractCredentials(HttpServletRequest request) {
		String grantType = request.getParameter("grant_type");
		if (grantType != null && grantType.equals("password")) {
			UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
					request.getParameter("username"), request.getParameter("password"));
			result.setDetails(authenticationDetailsSource.buildDetails(request));
			return result;
		}
		return null;
	}

	private Set<String> getScope(HttpServletRequest request) {
		return OAuth2Utils.parseParameterList(request.getParameter("scope"));
	}
	
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	public void destroy() {
	}

}
