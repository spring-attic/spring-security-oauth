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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.RandomValueTokenServices;

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

	private RandomValueTokenServices providerTokenServices = new RandomValueTokenServices();

	private ClientDetailsService clientDetailsService = new ClientDetailsService() {

		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return new BaseClientDetails("resource", "scope", "password", "ROLE_USER");
		}
	};

	private Map<String, String> parameters;

	public TestResourceOwnerPasswordTokenGranter() {
		providerTokenServices.setTokenStore(new InMemoryTokenStore());
		parameters = new HashMap<String, String>();
		parameters.put("username", "foo");
		parameters.put("password", "bar");
	}

	@Test
	public void testSunnyDay() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService);
		granter.grant("password", parameters, "client", Collections.singleton("scope"));
	}

	@Test(expected = InvalidGrantException.class)
	public void testBadCredentials() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new BadCredentialsException("test");
			}
		}, providerTokenServices, clientDetailsService);
		granter.grant("password", parameters, "client", Collections.singleton("scope"));
	}

	@Test(expected = InvalidGrantException.class)
	public void testUnauthenticated() {
		validUser = new UsernamePasswordAuthenticationToken("foo", "bar");
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService);
		granter.grant("password", parameters, "client", Collections.singleton("scope"));
	}

}
