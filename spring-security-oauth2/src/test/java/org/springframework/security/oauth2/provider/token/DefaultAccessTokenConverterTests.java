/*
 * Copyright 2013-2014 the original author or authors.
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

package org.springframework.security.oauth2.provider.token;

import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;


import static java.util.Collections.singleton;
import static java.util.Collections.singletonMap;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Dave Syer
 *
 */
public class DefaultAccessTokenConverterTests {

	private String ROLE_CLIENT = "ROLE_CLIENT";
	private String ROLE_USER = "ROLE_USER";

	private DefaultAccessTokenConverter converter = new DefaultAccessTokenConverter();

	private UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken("foo",
			"bar", singleton(new SimpleGrantedAuthority(ROLE_USER)));

	private OAuth2Request request;

	@Before
	public void init() {
		request = RequestTokenFactory.createOAuth2Request(null, "id",
				AuthorityUtils.commaSeparatedStringToAuthorityList(ROLE_CLIENT), true, singleton("read"),
				singleton("resource"), null, null, null);
	}

	@Test
	public void extractAuthentication() {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
		OAuth2Authentication authentication = new OAuth2Authentication(request, userAuthentication);
		token.setScope(authentication.getOAuth2Request().getScope());
		Map<String, ?> map = converter.convertAccessToken(token, authentication);
		assertTrue(map.containsKey(AccessTokenConverter.AUD));
		assertTrue(map.containsKey(AccessTokenConverter.SCOPE));
		assertTrue(map.containsKey(AccessTokenConverter.AUTHORITIES));
		assertEquals(singleton(ROLE_USER), map.get(AccessTokenConverter.AUTHORITIES));
		OAuth2Authentication extracted = converter.extractAuthentication(map);
		assertTrue(extracted.getOAuth2Request().getResourceIds().contains("resource"));
		assertEquals("[ROLE_USER]", extracted.getAuthorities().toString());
	}

	@Test
	public void extractAuthenticationFromClientToken() {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
		OAuth2Authentication authentication = new OAuth2Authentication(request, null);
		token.setScope(authentication.getOAuth2Request().getScope());
		Map<String, ?> map = converter.convertAccessToken(token, authentication);
		assertTrue(map.containsKey(AccessTokenConverter.AUD));
		assertTrue(map.containsKey(AccessTokenConverter.SCOPE));
		assertTrue(map.containsKey(AccessTokenConverter.AUTHORITIES));
		assertEquals(singleton(ROLE_CLIENT), map.get(AccessTokenConverter.AUTHORITIES));
		OAuth2Authentication extracted = converter.extractAuthentication(map);
		assertTrue(extracted.getOAuth2Request().getResourceIds().contains("resource"));
		assertEquals("[ROLE_CLIENT]", extracted.getAuthorities().toString());
	}

	@Test
	public void extractAuthenticationFromClientTokenSingleValuedAudience() {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
		OAuth2Authentication authentication = new OAuth2Authentication(request, null);
		token.setScope(authentication.getOAuth2Request().getScope());
		Map<String, Object> map = new LinkedHashMap<String, Object>(converter.convertAccessToken(token, authentication));
		@SuppressWarnings("unchecked")
		Object aud = ((Collection<Object>)map.get(AccessTokenConverter.AUD)).iterator().next();
		map.put(AccessTokenConverter.AUD, aud);
		assertTrue(map.containsKey(AccessTokenConverter.AUD));
		OAuth2Authentication extracted = converter.extractAuthentication(map);
		assertEquals("["+aud+"]", extracted.getOAuth2Request().getResourceIds().toString());
	}

	// gh-745
	@Test
	public void extractAuthenticationSingleScopeString() {
		String scope = "read";
		Map<String, Object> tokenAttrs = new HashMap<String, Object>();
		tokenAttrs.put(AccessTokenConverter.SCOPE, scope);
		OAuth2Authentication authentication = converter.extractAuthentication(tokenAttrs);
		assertEquals(Collections.singleton(scope), authentication.getOAuth2Request().getScope());
	}

	// gh-745
	@Test
	public void extractAuthenticationMultiScopeCollection() {
		Set<String> scopes = new HashSet<String>(Arrays.asList("read", "write", "read-write"));
		Map<String, Object> tokenAttrs = new HashMap<String, Object>();
		tokenAttrs.put(AccessTokenConverter.SCOPE, scopes);
		OAuth2Authentication authentication = converter.extractAuthentication(tokenAttrs);
		assertEquals(scopes, authentication.getOAuth2Request().getScope());
	}

	// gh-836 (passes incidentally per gh-745)
	@Test
	public void extractAuthenticationMultiScopeString() {
		String scopes = "read write read-write";
		assertEquals(new HashSet<String>(Arrays.asList(scopes.split(" "))),
						converter.extractAuthentication(singletonMap(AccessTokenConverter.SCOPE,
										scopes)).getOAuth2Request().getScope());
	}

	// gh-745
	@Test
	public void extractAccessTokenSingleScopeString() {
		String scope = "read";
		Map<String, Object> tokenAttrs = new HashMap<String, Object>();
		tokenAttrs.put(AccessTokenConverter.SCOPE, scope);
		OAuth2AccessToken accessToken = converter.extractAccessToken("token-value", tokenAttrs);
		assertEquals(Collections.singleton(scope), accessToken.getScope());
	}

	// gh-745
	@Test
	public void extractAccessTokenMultiScopeCollection() {
		Set<String> scopes = new HashSet<String>(Arrays.asList("read", "write", "read-write"));
		Map<String, Object> tokenAttrs = new HashMap<String, Object>();
		tokenAttrs.put(AccessTokenConverter.SCOPE, scopes);
		OAuth2AccessToken accessToken = converter.extractAccessToken("token-value", tokenAttrs);
		assertEquals(scopes, accessToken.getScope());
	}

	// gh-836
	@Test
	public void extractAccessTokenMultiScopeString() {
		String scopes = "read write read-write";
		assertEquals(new HashSet<String>(Arrays.asList(scopes.split(" "))),
						converter.extractAccessToken("token-value",
										singletonMap(AccessTokenConverter.SCOPE, scopes)).getScope());
	}

}
