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
package org.springframework.security.oauth2.provider.password;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;

/**
 * @author Dave Syer
 * 
 */
public class TestResourceOwnerPasswordTokenGranter {

	protected Authentication validUser = new UsernamePasswordAuthenticationToken("foo", "bar",
			Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));

	private AuthenticationManager authenticationManager = new AuthenticationManager() {
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return validUser;
		}
	};

	private DefaultTokenServices providerTokenServices = new DefaultTokenServices();

	private ClientDetailsService clientDetailsService = new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return new BaseClientDetails("foo", "resource", "scope", "password", "ROLE_USER");
		}
	};

	private AuthorizationRequest authorizationRequest;

	public TestResourceOwnerPasswordTokenGranter() {
		providerTokenServices.setTokenStore(new InMemoryTokenStore());
		Map<String, String> parameters = new HashMap<String, String>();
		parameters.put("username", "foo");
		parameters.put("password", "bar");
		parameters.put("client_id", "client");
		authorizationRequest = new DefaultAuthorizationRequest(parameters);
	}

	@Test
	public void testSunnyDay() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService);
		OAuth2AccessToken token = granter.grant("password", authorizationRequest);
		OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
		assertTrue(authentication.isAuthenticated());
	}

	@Test(expected = InvalidGrantException.class)
	public void testBadCredentials() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new BadCredentialsException("test");
			}
		}, providerTokenServices, clientDetailsService);
		granter.grant("password", authorizationRequest);
	}
	
	@Test(expected = InvalidGrantException.class)
	public void testAccountLocked() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new LockedException("test");
			}
		}, providerTokenServices, clientDetailsService);
		granter.grant("password", authorizationRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testUnauthenticated() {
		validUser = new UsernamePasswordAuthenticationToken("foo", "bar");
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService);
		granter.grant("password", authorizationRequest);
	}

}
