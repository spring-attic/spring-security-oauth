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
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class TestOAuth2SecurityExpressionRoot {

	@Test
	public void testOauthClient() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"))
				.addClientDetails(new BaseClientDetails("foo", "", "", "client_credentials", "ROLE_CLIENT"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertTrue(new OAuth2SecurityExpressionRoot(oAuth2Authentication).oauthClientHasAnyRole("ROLE_CLIENT"));
	}

	@Test
	public void testScopes() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		OAuth2SecurityExpressionRoot root = new OAuth2SecurityExpressionRoot(oAuth2Authentication);
		root.setThrowExceptionOnInvalidScope(false);
		assertTrue(root.oauthHasAnyScope("read"));
	}

	@Test(expected = InsufficientScopeException.class)
	public void testScopesWithException() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertTrue(new OAuth2SecurityExpressionRoot(oAuth2Authentication).oauthHasAnyScope("foo"));
	}

	@Test(expected = InsufficientScopeException.class)
	public void testInsufficientScope() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertFalse(new OAuth2SecurityExpressionRoot(oAuth2Authentication).oauthHasAnyScope("foo"));
		assertFalse(new OAuth2SecurityExpressionRoot(oAuth2Authentication).oauthSufficientScope(false));
	}

	@Test
	public void testSufficientScope() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertTrue(new OAuth2SecurityExpressionRoot(oAuth2Authentication).oauthHasAnyScope("read"));
		assertTrue(new OAuth2SecurityExpressionRoot(oAuth2Authentication).oauthSufficientScope(true));
	}

	@Test
	public void testSufficientScopeWithNoPreviousScopeDecision() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"))
				.approved(true);
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertTrue(new OAuth2SecurityExpressionRoot(oAuth2Authentication).oauthIsClient());
		assertFalse(new OAuth2SecurityExpressionRoot(oAuth2Authentication).oauthSufficientScope(false));
	}

	@Test
	public void testNonOauthClient() throws Exception {
		Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
		assertFalse(new OAuth2SecurityExpressionRoot(clientAuthentication).oauthClientHasAnyRole("ROLE_USER"));
	}

	@Test
	public void testClientOnly() throws Exception {
		AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
		request = request.approved(true);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar",
				Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(request, userAuthentication);
		assertFalse(new OAuth2SecurityExpressionRoot(oAuth2Authentication).oauthIsClient());
		assertTrue(new OAuth2SecurityExpressionRoot(new OAuth2Authentication(request, null)).oauthIsClient());
	}

	@Test
	public void testOAuthUser() throws Exception {
		AuthorizationRequest clientAuthentication = new AuthorizationRequest("foo", Collections.singleton("read"))
				.approved(true);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar",
				Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertTrue(new OAuth2SecurityExpressionRoot(oAuth2Authentication).oauthIsUser());
		assertFalse(new OAuth2SecurityExpressionRoot(new OAuth2Authentication(clientAuthentication, null))
				.oauthIsUser());
	}

}
