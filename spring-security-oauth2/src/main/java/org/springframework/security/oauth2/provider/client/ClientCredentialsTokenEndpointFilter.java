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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import org.springframework.web.HttpRequestMethodNotSupportedException;

/**
 * A filter and authentication endpoint for the OAuth2 Token Endpoint. Allows clients to authenticate using request
 * parameters if included as a security filter, as permitted by the specification (but not recommended). It is
 * recommended by the specification that you permit HTTP basic authentication for clients, and not use this filter at
 * all.
 * 
 * @author Dave Syer
 * @author Lachezar Balev
 */
public class ClientCredentialsTokenEndpointFilter extends AbstractAuthenticationProcessingFilter {

	private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

	private boolean allowOnlyPost = false;

	public ClientCredentialsTokenEndpointFilter() {
		this("/oauth/token");
	}

	public ClientCredentialsTokenEndpointFilter(String path) {
		this(Arrays.asList(path));
	}

	/**
	 * Creates a new filter which will be effective only when the request matches at least one of the given paths. The
	 * context of the running application will be taken into account.
	 * 
	 * @param paths the paths against which the request should be matched. Cannot be null or empty.
	 */
	public ClientCredentialsTokenEndpointFilter(Collection<String> paths) {
		super(new ClientCredentialsRequestMatcher(paths));
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
			throw new HttpRequestMethodNotSupportedException(request.getMethod(), new String[] { "POST" });
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

		if (clientSecret == null) {
			clientSecret = "";
		}

		clientId = clientId.trim();
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(clientId,
				clientSecret);

		return this.getAuthenticationManager().authenticate(authRequest);

	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, chain, authResult);
		chain.doFilter(request, response);
	}

	/**
	 * A request matcher which determines when the client credentials token endpoint filter will be effective in the
	 * filter chain. The filter will be considered only when the request matches against the paths with which the
	 * matcher had been initialized. The context path of the application is considered.
	 * 
	 * @author Dave Syer
	 * @author Lachezar Balev
	 */
	protected static class ClientCredentialsRequestMatcher implements RequestMatcher {

		private final Collection<String> pathsToMatch = new ArrayList<String>(3);

		/**
		 * Creates a new request matcher that matches the request against the given <code>path</code>.
		 * 
		 * @param path the path against which the request should be matched. Required.
		 */
		public ClientCredentialsRequestMatcher(String path) {
			if (path == null) {
				throw new NullPointerException("The path cannot be null!");
			}
			this.pathsToMatch.add(path);
		}

		/**
		 * Creates a new request matcher that matches the request against the given <code>paths</code>.
		 * 
		 * @param paths a collection with paths, cannot be null or empty.
		 */
		ClientCredentialsRequestMatcher(Collection<String> paths) {
			if (paths == null) {
				// java 6...
				throw new NullPointerException("Paths cannot be null!");
			}
			else if (paths.isEmpty()) {
				throw new IllegalArgumentException("The paths cannot be empty!");
			}
			this.pathsToMatch.addAll(paths);
		}

		@Override
		public boolean matches(HttpServletRequest request) {

			String clientId = request.getParameter("client_id");
			if (clientId == null) {
				// Give basic auth a chance to work instead (it's the preferred anyway)
				return false;
			}

			String uri = request.getRequestURI();
			int pathParamIndex = uri.indexOf(';');
			if (pathParamIndex > 0) {
				// strip everything after the first semi-colon
				uri = uri.substring(0, pathParamIndex);
			}

			for (String path : pathsToMatch) {
				String matchAgainst = "".equals(request.getContextPath()) ? path : request.getContextPath() + path;
				if (uri.endsWith(matchAgainst)) {
					return true;
				}
			}

			return false;
		}

	}

}
