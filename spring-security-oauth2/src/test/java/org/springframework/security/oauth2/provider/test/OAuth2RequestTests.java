/*
 * Copyright 20013-2014 the original author or authors.
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

package org.springframework.security.oauth2.provider.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;

/**
 * @author Dave Syer
 *
 */
public class OAuth2RequestTests {

	private Map<String, String> parameters;

	@Before
	public void prepare() {
		parameters = new HashMap<String, String>();
		parameters.put("client_id", "theClient");
	}

	@Test
	public void testBaseMethods() throws Exception {
		parameters.put("response_type", "token");
		OAuth2Request authorizationRequest = createFromParameters(parameters);
		assertEquals("theClient", authorizationRequest.getClientId());
	}

	@Test
	public void testImplicitGrantType() throws Exception {
		parameters.put("response_type", "token");
		OAuth2Request authorizationRequest = createFromParameters(parameters);
		assertEquals("implicit", authorizationRequest.getGrantType());
	}

	@Test
	public void testOtherGrantType() throws Exception {
		parameters.put("grant_type", "password");
		OAuth2Request authorizationRequest = createFromParameters(parameters);
		assertEquals("password", authorizationRequest.getGrantType());
	}

	// gh-724
	@Test
	public void testResourceIdsConstructorAssignment() {
		Set<String> resourceIds = new HashSet<String>(Arrays.asList("resourceId-1", "resourceId-2"));
		OAuth2Request request = new OAuth2Request(
				Collections.<String, String>emptyMap(), "clientId", Collections.<GrantedAuthority>emptyList(),
				false, Collections.<String>emptySet(), resourceIds, "redirectUri", Collections.<String>emptySet(),
				Collections.<String, Serializable>emptyMap());
		assertNotSame("resourceIds are the same", resourceIds, request.getResourceIds());
	}

	private OAuth2Request createFromParameters(Map<String, String> parameters) {
		OAuth2Request request = RequestTokenFactory.createOAuth2Request(parameters,
				parameters.get(OAuth2Utils.CLIENT_ID), false,
				OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)));
		return request;
	}

}
