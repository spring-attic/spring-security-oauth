/*
 * Copyright 2010-2012 the original author or authors.
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

package org.springframework.security.oauth2.client.filter;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

/**
 * An OAuth2 client filter that can be used to acquire an OAuth2 access token from an authorization server, and load an
 * authentication object into the SecurityContext
 * 
 * @author Vidya Valmikinathan
 * 
 */
public class OAuth2ClientAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	public OAuth2RestOperations restTemplate;

	private ResourceServerTokenServices tokenServices;

	/**
	 * Reference to a CheckTokenServices that can validate an OAuth2AccessToken
	 * 
	 * @param tokenServices
	 */
	public void setTokenServices(ResourceServerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	/**
	 * A rest template to be used to obtain an access token.
	 * 
	 * @param restTemplate a rest template
	 */
	public void setRestTemplate(OAuth2RestOperations restTemplate) {
		this.restTemplate = restTemplate;
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

		OAuth2AccessToken accessToken = restTemplate.getAccessToken();
		try {
			OAuth2Authentication result = tokenServices.loadAuthentication(accessToken.getValue());
			return result;
		}
		catch (InvalidTokenException e) {
			throw new BadCredentialsException("Could not obtain user details from token", e);
		}

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