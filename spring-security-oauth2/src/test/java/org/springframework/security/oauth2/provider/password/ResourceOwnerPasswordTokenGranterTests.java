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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * @author Dave Syer
 * 
 */
public class ResourceOwnerPasswordTokenGranterTests {

	private Authentication validUser = new UsernamePasswordAuthenticationToken("foo", "bar",
			Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));

	private BaseClientDetails client = new BaseClientDetails("foo", "resource", "scope", "password", "ROLE_USER");

	private AuthenticationManager authenticationManager = new AuthenticationManager() {
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return validUser;
		}
	};

	private DefaultTokenServices providerTokenServices = new DefaultTokenServices();

	private ClientDetailsService clientDetailsService = new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return client;
		}
	};

	private OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);

	private TokenRequest tokenRequest;

	public ResourceOwnerPasswordTokenGranterTests() {
		String clientId = "client";
		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId(clientId);

		providerTokenServices.setTokenStore(new InMemoryTokenStore());
		Map<String, String> parameters = new HashMap<String, String>();
		parameters.put("username", "foo");
		parameters.put("password", "bar");
		parameters.put("client_id", clientId);

		tokenRequest = requestFactory.createTokenRequest(parameters, clientDetails);
	}

	@Test
	public void testSunnyDay() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("password", tokenRequest);
		OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
		assertTrue(authentication.isAuthenticated());
	}

	@Test
	public void testPasswordRemoved() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("password", tokenRequest);
		OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
		assertNotNull(authentication.getOAuth2Request().getRequestParameters().get("username"));
		assertNull(authentication.getOAuth2Request().getRequestParameters().get("password"));
	}

	@Test
	public void testExtraParameters() {
		authenticationManager = new AuthenticationManager() {
			@Override
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				if (authentication instanceof UsernamePasswordAuthenticationToken) {
					UsernamePasswordAuthenticationToken user = (UsernamePasswordAuthenticationToken) authentication;
					user = new UsernamePasswordAuthenticationToken(user.getPrincipal(), "N/A",
							AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
					@SuppressWarnings("unchecked")
					Map<String,String> details = (Map<String,String>) authentication.getDetails();
					assertNull(details.get("password"));
					return user;
				}
				return authentication;
			}
		};
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("password", tokenRequest);
		OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
		assertTrue(authentication.isAuthenticated());
		assertNull(authentication.getUserAuthentication().getDetails());
	}

	@Test(expected = InvalidGrantException.class)
	public void testBadCredentials() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new BadCredentialsException("test");
			}
		}, providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("password", tokenRequest);
	}

	@Test(expected = InvalidClientException.class)
	public void testGrantTypeNotSupported() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService, requestFactory);
		client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
		granter.grant("password", tokenRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testAccountLocked() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new LockedException("test");
			}
		}, providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("password", tokenRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testUnauthenticated() {
		validUser = new UsernamePasswordAuthenticationToken("foo", "bar");
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("password", tokenRequest);
	}

}
