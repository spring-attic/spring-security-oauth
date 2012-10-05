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

package org.springframework.security.oauth2.provider.code;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.security.oauth2.provider.AuthorizationRequest.REDIRECT_URI;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 * 
 */
public class TestAuthorizationCodeTokenGranter {

	private DefaultTokenServices providerTokenServices = new DefaultTokenServices();

	private BaseClientDetails client = new BaseClientDetails("foo", "resource", "scope", "authorization_code",
			"ROLE_CLIENT");

	private ClientDetailsService clientDetailsService = new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return client;
		}
	};

	private AuthorizationCodeServices authorizationCodeServices = new InMemoryAuthorizationCodeServices();

	private Map<String, String> parameters = new HashMap<String, String>();

	public TestAuthorizationCodeTokenGranter() {
		providerTokenServices.setTokenStore(new InMemoryTokenStore());
	}

	@Test
	public void testAuthorizationCodeGrant() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("foo",
				Arrays.asList("scope"));
		authorizationRequest.setApproved(true);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new AuthorizationRequestHolder(
				authorizationRequest, userAuthentication));
		parameters.putAll(authorizationRequest.getAuthorizationParameters());
		parameters.put("code", code);
		authorizationRequest.setAuthorizationParameters(parameters);
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService);
		OAuth2AccessToken token = granter.grant("authorization_code", authorizationRequest);
		assertTrue(providerTokenServices.loadAuthentication(token.getValue()).isAuthenticated());
	}

	@Test
	public void testAuthorizationParametersPreserved() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(
				commaDelimitedStringToMap("foo=bar,client_id=foo"));
		authorizationRequest.setApproved(true);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new AuthorizationRequestHolder(
				authorizationRequest, userAuthentication));
		parameters.putAll(authorizationRequest.getAuthorizationParameters());
		parameters.put("code", code);
		authorizationRequest.setAuthorizationParameters(parameters);
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService);
		OAuth2AccessToken token = granter.grant("authorization_code", authorizationRequest);
		AuthorizationRequest finalRequest = providerTokenServices.loadAuthentication(token.getValue())
				.getAuthorizationRequest();
		assertEquals(code, finalRequest.getAuthorizationParameters().get("code"));
		assertEquals("bar", finalRequest.getAuthorizationParameters().get("foo"));
	}

	@Test
	public void testAuthorizationRequestPreserved() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(
				commaDelimitedStringToMap("client_id=foo,scope=read"));
		authorizationRequest.setResourceIds(Collections.singleton("resource"));
		authorizationRequest.setApproved(true);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new AuthorizationRequestHolder(
				authorizationRequest, userAuthentication));
		parameters.put("client_id", "foo");
		parameters.put("code", code);
		authorizationRequest.setAuthorizationParameters(parameters);
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService);
		OAuth2AccessToken token = granter.grant("authorization_code", authorizationRequest);
		AuthorizationRequest finalRequest = providerTokenServices.loadAuthentication(token.getValue())
				.getAuthorizationRequest();
		assertEquals("[read]", finalRequest.getScope().toString());
		assertEquals("[resource]", finalRequest.getResourceIds().toString());
		assertTrue(finalRequest.isApproved());
	}

	private static Map<String, String> commaDelimitedStringToMap(String string) {
		Map<String, String> result = new HashMap<String, String>();
		for (String entry : StringUtils.commaDelimitedListToSet(string)) {
			String[] values = StringUtils.delimitedListToStringArray(entry, "=");
			result.put(values[0], values.length < 2 ? null : values[1]);
		}
		return result;
	}

	@Test
	public void testAuthorizationCodeGrantWithNoClientAuthorities() {
		client.setAuthorities(Collections.<GrantedAuthority> emptySet());
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("foo",
				Arrays.asList("scope"));
		authorizationRequest.setApproved(true);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new AuthorizationRequestHolder(
				authorizationRequest, userAuthentication));
		parameters.putAll(authorizationRequest.getAuthorizationParameters());
		parameters.put("code", code);
		authorizationRequest.setAuthorizationParameters(parameters);
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService);
		OAuth2AccessToken token = granter.grant("authorization_code", authorizationRequest);
		assertTrue(providerTokenServices.loadAuthentication(token.getValue()).isAuthenticated());
	}

	@Test
	public void testAuthorizationRedirectMismatch() {
		Map<String, String> initialParameters = new HashMap<String, String>();
		initialParameters.put(REDIRECT_URI, "https://redirectMe");
		DefaultAuthorizationRequest initialRequest = new DefaultAuthorizationRequest(initialParameters);
		// we fake a valid resolvedRedirectUri because without the client would never come this far
		initialRequest.setRedirectUri(initialParameters.get(REDIRECT_URI));

		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new AuthorizationRequestHolder(initialRequest,
				userAuthentication));

		Map<String, String> authorizationParameters = new HashMap<String, String>();
		authorizationParameters.put("code", code);
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(initialParameters);
		authorizationRequest.setAuthorizationParameters(authorizationParameters);

		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService);
		try {
			granter.getOAuth2Authentication(authorizationRequest);
			fail("RedirectMismatchException because of null redirect_uri in authorizationRequest");
		}
		catch (RedirectMismatchException e) {
		}
	}

}
