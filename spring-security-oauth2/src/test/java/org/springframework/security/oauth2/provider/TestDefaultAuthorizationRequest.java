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

package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.oauth2.provider.AuthorizationRequest.REDIRECT_URI;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 * @author Christian Hilmersson
 *
 */
public class TestDefaultAuthorizationRequest {

	private Map<String, String> parameters;

	@Before
	public void prepare() {
		parameters = new HashMap<String, String>();
		parameters.put("client_id", "theClient");
		parameters.put("state", "XYZ123");
		parameters.put("redirect_uri", "http://www.callistaenterprise.se");
	}
	
	@Test
	public void testApproval() throws Exception {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(parameters);
		assertFalse(authorizationRequest.isApproved());
		authorizationRequest.setApproved(true);
		assertTrue(authorizationRequest.isApproved());
	}

	@Test
	public void testScopeSetInParameters() throws Exception {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(parameters);
		authorizationRequest.setScope(StringUtils.commaDelimitedListToSet("foo,bar"));
		assertEquals("bar foo", authorizationRequest.getAuthorizationParameters().get(AuthorizationRequest.SCOPE));
	}

	@Test
	public void testClientIdNotOverwitten() throws Exception {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList("read"));
		parameters = new HashMap<String, String>();
		authorizationRequest.setAuthorizationParameters(parameters);
		assertEquals("client", authorizationRequest.getClientId());
		assertEquals("read", authorizationRequest.getAuthorizationParameters().get(AuthorizationRequest.SCOPE));
	}
	
	@Test
	public void testPasswordSetAndRemovedFromParameters() throws Exception {
		parameters.put("username", "sample");
		parameters.put("password", "testing");
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(parameters);
		assertEquals("testing", authorizationRequest.getAuthorizationParameters().get("password"));

		authorizationRequest.remove(Arrays.asList("password"));
		assertNotNull(authorizationRequest.getAuthorizationParameters().get("username"));
		assertNull(authorizationRequest.getAuthorizationParameters().get("password"));
	}

	@Test
	public void testScopeWithSpace() throws Exception {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(parameters);
		authorizationRequest.setScope(Collections.singleton("foo bar"));
		assertEquals("bar foo", authorizationRequest.getAuthorizationParameters().get(AuthorizationRequest.SCOPE));
	}

	/**
	 * Tests that the construction of an AuthorizationRequest objects using
	 * a parameter Map maintains a sorted order of the scope.
	 */
	@Test
	public void testScopeSortedOrder() {
		// Arbitrary scope set
		String scopeString = "AUTHORITY_A AUTHORITY_X AUTHORITY_B AUTHORITY_C AUTHORITY_D " +
				"AUTHORITY_Y AUTHORITY_V AUTHORITY_ZZ AUTHORITY_DYV AUTHORITY_ABC AUTHORITY_BA " +
				"AUTHORITY_AV AUTHORITY_AB AUTHORITY_CDA AUTHORITY_ABCD";
		// Create correctly sorted scope string
		Set<String> sortedSet = OAuth2Utils.parseParameterList(scopeString);
		Assert.assertTrue(sortedSet instanceof SortedSet);
		String sortedScopeString = OAuth2Utils.formatParameterList(sortedSet);

		parameters.put("scope", scopeString);
		AuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(parameters);
				
		// Assert that both the scope parameter and the scope Set of 
		// the constructed AuthorizationRequest are sorted
		Assert.assertEquals(sortedScopeString, OAuth2Utils.formatParameterList(authorizationRequest.getScope()));
		Assert.assertEquals(sortedScopeString, authorizationRequest.getAuthorizationParameters().get("scope"));
	}	

	@Test
	public void testRedirectUriDefaultsToMap() {
		parameters.put("scope", "one two");
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(parameters);
		assertEquals("XYZ123", authorizationRequest.getState());
		assertEquals("theClient", authorizationRequest.getClientId());
		assertEquals("http://www.callistaenterprise.se", authorizationRequest.getRedirectUri());
		assertEquals("http://www.callistaenterprise.se", authorizationRequest.getAuthorizationParameters().get(REDIRECT_URI));
		assertEquals("[one, two]", authorizationRequest.getScope().toString());
	}

}
