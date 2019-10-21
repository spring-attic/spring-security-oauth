/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 * @author Christian Hilmersson
 *
 */
public class AuthorizationRequestTests {

	private Map<String, String> parameters;

	@Before
	public void prepare() {
		parameters = new HashMap<String, String>();
		parameters.put("client_id", "theClient");
		parameters.put("state", "XYZ123");
		parameters.put("redirect_uri", "https://callistaenterprise.se/");
	}
	
	@Test
	public void testApproval() throws Exception {
		AuthorizationRequest authorizationRequest = createFromParameters(parameters);
		assertFalse(authorizationRequest.isApproved());
		authorizationRequest.setApproved(true);
		assertTrue(authorizationRequest.isApproved());
	}

	/**
	 * Ensure that setting the scope does not alter the original request parameters.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testScopeNotSetInParameters() throws Exception {
		parameters.put("scope", "read,write");
		AuthorizationRequest authorizationRequest = createFromParameters(parameters);
		authorizationRequest.setScope(StringUtils.commaDelimitedListToSet("foo,bar"));
		assertFalse(authorizationRequest.getRequestParameters().get(OAuth2Utils.SCOPE).contains("bar"));
		assertFalse(authorizationRequest.getRequestParameters().get(OAuth2Utils.SCOPE).contains("foo"));
	}

	/**
	 * Ensure that setting a single value scope which contains spaces
	 * will result in exploding multiple scopes.
	 */
	@Test
	public void testSpaceSeparatedScopesAreExploded() throws Exception {
		AuthorizationRequest authorizationRequest = createFromParameters(parameters);
		String multiScope = "foo bar";
		authorizationRequest.setScope(Collections.singleton(multiScope));
		assertEquals(authorizationRequest.getScope().size(), 2);
		assertTrue(authorizationRequest.getScope().containsAll(Arrays.asList("foo", "bar")));
		assertFalse(authorizationRequest.getScope().contains(multiScope));
	}

	/**
	 * Ensure that setting a single value scope which contains commas
	 * will result in exploding multiple scopes.
	 */
	@Test
	public void testCommaInScopeIsAllowed() throws Exception {
		AuthorizationRequest authorizationRequest = createFromParameters(parameters);
		String multiScope = "foo,bar";
		authorizationRequest.setScope(Collections.singleton(multiScope));
		assertEquals(authorizationRequest.getScope().size(), 1);
		assertTrue(authorizationRequest.getScope().contains(multiScope));
	}

	@Test
	public void testClientIdNotOverwitten() throws Exception {
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("client", Arrays.asList("read"));
		parameters = new HashMap<String, String>();
		parameters.put("scope", "write");
		authorizationRequest.setRequestParameters(parameters);

		assertEquals("client", authorizationRequest.getClientId());
		assertEquals(1, authorizationRequest.getScope().size());
		assertTrue(authorizationRequest.getScope().contains("read"));
		assertFalse(authorizationRequest.getRequestParameters().get(OAuth2Utils.SCOPE).contains("read"));
	}

	@Test
	public void testScopeWithSpace() throws Exception {
		parameters.put("scope", "bar foo");
		AuthorizationRequest authorizationRequest = createFromParameters(parameters);
		authorizationRequest.setScope(Collections.singleton("foo bar"));
		assertEquals("bar foo", authorizationRequest.getRequestParameters().get(OAuth2Utils.SCOPE));
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
		assertTrue(sortedSet instanceof SortedSet);
		String sortedScopeString = OAuth2Utils.formatParameterList(sortedSet);

		parameters.put("scope", scopeString);
		AuthorizationRequest authorizationRequest = createFromParameters(parameters);
		authorizationRequest.setScope(sortedSet);
				
		// Assert that the scope parameter is still sorted
		
		String fromAR = OAuth2Utils.formatParameterList(authorizationRequest.getScope());
		
		assertEquals(sortedScopeString, fromAR);
	}	

	@Test
	public void testRedirectUriDefaultsToMap() {
		parameters.put("scope", "one two");
		AuthorizationRequest authorizationRequest = createFromParameters(parameters);

		assertEquals("XYZ123", authorizationRequest.getState());
		assertEquals("theClient", authorizationRequest.getClientId());
		assertEquals("https://callistaenterprise.se/", authorizationRequest.getRedirectUri());
		assertEquals("https://callistaenterprise.se/", authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI));
		assertEquals("[one, two]", authorizationRequest.getScope().toString());
	}

	@Test
	public void testSerialization() {
		AuthorizationRequest authorizationRequest = createFromParameters(parameters);
		AuthorizationRequest other = SerializationUtils.deserialize(
				SerializationUtils.serialize(authorizationRequest));
		assertEquals(authorizationRequest, other);
	}

	private AuthorizationRequest createFromParameters(Map<String, String> authorizationParameters) {
		AuthorizationRequest request = new AuthorizationRequest(authorizationParameters, Collections.<String, String> emptyMap(), 
				authorizationParameters.get(OAuth2Utils.CLIENT_ID), 
				OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.SCOPE)), null,
				null, false, authorizationParameters.get(OAuth2Utils.STATE), 
				authorizationParameters.get(OAuth2Utils.REDIRECT_URI), 
				OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.RESPONSE_TYPE)));
		return request;
	}
	
}
