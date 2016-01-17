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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidCodeVerifierException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * @author Dave Syer
 * 
 */
public class AuthorizationCodeTokenGranterTests {

	private DefaultTokenServices providerTokenServices = new DefaultTokenServices();

	private BaseClientDetails client = new BaseClientDetails("foo", "resource", "scope", "authorization_code",
			"ROLE_CLIENT");

	private ClientDetailsService clientDetailsService = new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return client;
		}
	};

	private AuthorizationCodeServices authorizationCodeServices = new InMemoryAuthorizationCodeServices();
	
	private OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);

	private Map<String, String> parameters = new HashMap<String, String>();

	public AuthorizationCodeTokenGranterTests() {
		providerTokenServices.setTokenStore(new InMemoryTokenStore());
	}

	@Test
	public void testAuthorizationCodeGrant() {
		
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		
		parameters.clear();
		parameters.put(OAuth2Utils.CLIENT_ID, "foo");
		parameters.put(OAuth2Utils.SCOPE, "scope");
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request(parameters, "foo", true, Collections.singleton("scope"));
		
		String code = authorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(
				storedOAuth2Request, userAuthentication));
		parameters.putAll(storedOAuth2Request.getRequestParameters());
		parameters.put("code", code);
		
		TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
				
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("authorization_code", tokenRequest);
		assertTrue(providerTokenServices.loadAuthentication(token.getValue()).isAuthenticated());
	}

	@Test
	public void testAuthorizationCodeGrantWithPlainCodeChallenge() {

		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));

		parameters.clear();
		parameters.put(OAuth2Utils.CLIENT_ID, "foo");
		parameters.put(OAuth2Utils.SCOPE, "scope");
		parameters.put(OAuth2Utils.CODE_CHALLENGE, "plainCodeChallenge");
		parameters.put(OAuth2Utils.CODE_CHALLENGE_METHOD, "plain");
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request(parameters, "foo", true,
				Collections.singleton("scope"));

		String code = authorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request,
				userAuthentication));
		parameters.putAll(storedOAuth2Request.getRequestParameters());
		parameters.put("code", code);
		parameters.put(OAuth2Utils.CODE_VERIFIER, "plainCodeChallenge");

		TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);

		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("authorization_code", tokenRequest);
		assertTrue(providerTokenServices.loadAuthentication(token.getValue()).isAuthenticated());
	}

	@Test(expected = InvalidCodeVerifierException.class)
	public void testAuthorizationCodeGrantWithInvalidPlainCodeVerifier() {

		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));

		parameters.clear();
		parameters.put(OAuth2Utils.CLIENT_ID, "foo");
		parameters.put(OAuth2Utils.SCOPE, "scope");
		parameters.put(OAuth2Utils.CODE_CHALLENGE, "plainCodeChallenge");
		parameters.put(OAuth2Utils.CODE_CHALLENGE_METHOD, "plain");
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request(parameters, "foo", true,
				Collections.singleton("scope"));

		String code = authorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request,
				userAuthentication));
		parameters.putAll(storedOAuth2Request.getRequestParameters());
		parameters.put("code", code);
		parameters.put(OAuth2Utils.CODE_VERIFIER, "aDifferentPlainCodeVerifier");

		TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);

		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("authorization_code", tokenRequest);
	}

	@Test
	public void testAuthorizationCodeGrantWithS256CodeChallenge() {

		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));

		parameters.clear();
		parameters.put(OAuth2Utils.CLIENT_ID, "foo");
		parameters.put(OAuth2Utils.SCOPE, "scope");
		parameters.put(OAuth2Utils.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
		parameters.put(OAuth2Utils.CODE_CHALLENGE_METHOD, "S256");
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request(parameters, "foo", true,
				Collections.singleton("scope"));

		String code = authorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request,
				userAuthentication));
		parameters.putAll(storedOAuth2Request.getRequestParameters());
		parameters.put("code", code);
		parameters.put(OAuth2Utils.CODE_VERIFIER, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

		TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);

		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("authorization_code", tokenRequest);
		assertTrue(providerTokenServices.loadAuthentication(token.getValue()).isAuthenticated());
	}

	@Test(expected = InvalidCodeVerifierException.class)
	public void testAuthorizationCodeGrantWithInvalidS256CodeVerifier() {

		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));

		parameters.clear();
		parameters.put(OAuth2Utils.CLIENT_ID, "foo");
		parameters.put(OAuth2Utils.SCOPE, "scope");
		parameters.put(OAuth2Utils.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
		parameters.put(OAuth2Utils.CODE_CHALLENGE_METHOD, "S256");
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request(parameters, "foo", true,
				Collections.singleton("scope"));

		String code = authorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request,
				userAuthentication));
		parameters.putAll(storedOAuth2Request.getRequestParameters());
		parameters.put("code", code);
		parameters.put(OAuth2Utils.CODE_VERIFIER, "aaaaaaaaaaaa-mB92K27uhbUJU1p1r_wW1gFWFOEjXa");

		TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);

		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("authorization_code", tokenRequest);
		assertTrue(providerTokenServices.loadAuthentication(token.getValue()).isAuthenticated());
	}


	@Test
	public void testAuthorizationParametersPreserved() {
		
		parameters.clear();
		parameters.put("foo", "bar");
		parameters.put(OAuth2Utils.CLIENT_ID, "foo");
		parameters.put(OAuth2Utils.SCOPE, "scope");
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request(parameters, "foo", true, Collections.singleton("scope"));
		
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(
				storedOAuth2Request, userAuthentication));

		parameters.put("code", code);
		TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
		
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("authorization_code", tokenRequest);
		OAuth2Request finalRequest = providerTokenServices.loadAuthentication(token.getValue())
				.getOAuth2Request();
		assertEquals(code, finalRequest.getRequestParameters().get("code"));
		assertEquals("bar", finalRequest.getRequestParameters().get("foo"));
	}

	@Test
	public void testAuthorizationRequestPreserved() {
		
		parameters.clear();
		parameters.put(OAuth2Utils.CLIENT_ID, "foo");
		parameters.put(OAuth2Utils.SCOPE, "read");
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request(parameters, "foo", null, true, Collections.singleton("read"), Collections.singleton("resource"), null, null, null);
		
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(
				storedOAuth2Request, userAuthentication));

		parameters.put("code", code);
		// Ensure even if token request asks for more scope they are not granted
		parameters.put(OAuth2Utils.SCOPE, "read write");
		TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
		
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("authorization_code", tokenRequest);
		OAuth2Request finalRequest = providerTokenServices.loadAuthentication(token.getValue())
				.getOAuth2Request();
		assertEquals("[read]", finalRequest.getScope().toString());
		assertEquals("[resource]", finalRequest.getResourceIds().toString());
		assertTrue(finalRequest.isApproved());
	}

	@Test
	public void testAuthorizationCodeGrantWithNoClientAuthorities() {
		
		parameters.clear();
		parameters.put(OAuth2Utils.CLIENT_ID, "foo");
		parameters.put(OAuth2Utils.SCOPE, "scope");
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request(parameters, "foo", Collections.<GrantedAuthority> emptySet(), true, Collections.singleton("scope"), null, null, null, null);
		
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(
				storedOAuth2Request, userAuthentication));
		parameters.put("code", code);
		TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("authorization_code", tokenRequest);
		assertTrue(providerTokenServices.loadAuthentication(token.getValue()).isAuthenticated());
	}

	@Test
	public void testAuthorizationRedirectMismatch() {
		Map<String, String> initialParameters = new HashMap<String, String>();
		initialParameters.put(OAuth2Utils.REDIRECT_URI, "https://redirectMe");
		//AuthorizationRequest initialRequest = createFromParameters(initialParameters);
		// we fake a valid resolvedRedirectUri because without the client would never come this far
		//initialRequest.setRedirectUri(initialParameters.get(REDIRECT_URI));

		parameters.clear();
		parameters.put(OAuth2Utils.REDIRECT_URI, "https://redirectMe");
		parameters.put(OAuth2Utils.CLIENT_ID, "foo");
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request(parameters, "foo", null, true, null, null, "https://redirectMe", null, null);
		
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request,
				userAuthentication));

		Map<String, String> authorizationParameters = new HashMap<String, String>();
		authorizationParameters.put("code", code);
	
		//AuthorizationRequest oAuth2Request = createFromParameters(initialParameters);
		//oAuth2Request.setRequestParameters(authorizationParameters);

		TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
		tokenRequest.setRequestParameters(authorizationParameters);
		
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, clientDetailsService, requestFactory);
		try {
			granter.getOAuth2Authentication(client, tokenRequest);
			fail("RedirectMismatchException because of null redirect_uri in authorizationRequest");
		}
		catch (RedirectMismatchException e) {
		}
	}

}
