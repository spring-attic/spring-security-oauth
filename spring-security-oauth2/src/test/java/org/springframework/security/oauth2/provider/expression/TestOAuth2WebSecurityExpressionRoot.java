/*
 * Copyright 2002-2011 the original author or authors.
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

package org.springframework.security.oauth2.provider.expression;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.FilterInvocation;

/**
 * @author Dave Syer
 * 
 */
public class TestOAuth2WebSecurityExpressionRoot {

	@Test
	public void testOauthClient() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"),
				Collections.<GrantedAuthority> singleton(new SimpleGrantedAuthority("ROLE_USER")),
				Collections.singleton("bar"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		assertTrue(new OAuth2WebSecurityExpressionRoot(oAuth2Authentication, invocation, false).oauthClientHasAnyRole("ROLE_USER"));
	}

	@Test
	public void testScopes() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"),
				Collections.<GrantedAuthority> singleton(new SimpleGrantedAuthority("ROLE_USER")),
				Collections.singleton("bar"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		assertTrue(new OAuth2WebSecurityExpressionRoot(oAuth2Authentication, invocation, false).oauthHasAnyScope("read"));
	}

	@Test(expected=InvalidScopeException.class)
	public void testScopesWithException() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"),
				Collections.<GrantedAuthority> singleton(new SimpleGrantedAuthority("ROLE_USER")),
				Collections.singleton("bar"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		assertTrue(new OAuth2WebSecurityExpressionRoot(oAuth2Authentication, invocation, true).oauthHasAnyScope("write"));
	}

	@Test
	public void testNonOauthClient() throws Exception {
		Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		assertFalse(new OAuth2WebSecurityExpressionRoot(clientAuthentication, invocation, false).oauthClientHasAnyRole("ROLE_USER"));
	}

	@Test
	public void testClientOnly() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"),
				Collections.<GrantedAuthority> singleton(new SimpleGrantedAuthority("ROLE_USER")),
				Collections.singleton("bar"));
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		assertFalse(new OAuth2WebSecurityExpressionRoot(oAuth2Authentication, invocation, false).oauthIsClient());
		assertTrue(new OAuth2WebSecurityExpressionRoot(new OAuth2Authentication(clientAuthentication, null), invocation, false).oauthIsClient());
	}

	@Test
	public void testOAuthUser() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"),
				Collections.<GrantedAuthority> singleton(new SimpleGrantedAuthority("ROLE_USER")),
				Collections.singleton("bar")).denied(false);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		FilterInvocation invocation = new FilterInvocation("/foo", "GET");
		assertTrue(new OAuth2WebSecurityExpressionRoot(oAuth2Authentication, invocation, false).oauthIsUser());
		assertFalse(new OAuth2WebSecurityExpressionRoot(new OAuth2Authentication(clientAuthentication, null), invocation, false).oauthIsUser());
	}

}
