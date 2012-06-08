/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;

import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * @author Dave Syer
 *
 */
public class TestDefaultAuthorizationRequestFactory {
	
	private BaseClientDetails client = new BaseClientDetails();

	private DefaultAuthorizationRequestFactory factory = new DefaultAuthorizationRequestFactory(new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return client;
		}
	});
	
	@Before
	public void start() {
		client.setClientId("foo");
		client.setScope(Collections.singleton("bar"));
	}

	@Test
	public void testCreateAuthorizationRequest() {
		AuthorizationRequest request = factory.createAuthorizationRequest(Collections.<String,String>emptyMap(), Collections.<String,String>emptyMap(), "foo", "password", null);
		assertEquals("foo", request.getClientId());
	}

	@Test
	public void testCreateAuthorizationRequestWithDefaultScopes() {
		AuthorizationRequest request = factory.createAuthorizationRequest(Collections.<String,String>emptyMap(), Collections.<String,String>emptyMap(), "foo", "password", Collections.<String>emptySet());
		assertEquals("[bar]", request.getScope().toString());
	}

}
