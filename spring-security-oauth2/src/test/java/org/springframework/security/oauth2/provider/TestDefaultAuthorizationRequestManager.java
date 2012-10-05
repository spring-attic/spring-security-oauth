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
public class TestDefaultAuthorizationRequestManager {
	
	private BaseClientDetails client = new BaseClientDetails();

	private DefaultAuthorizationRequestManager factory = new DefaultAuthorizationRequestManager(new ClientDetailsService() {
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
		AuthorizationRequest request = factory.createAuthorizationRequest(Collections.singletonMap("client_id", "foo"));
		assertEquals("foo", request.getClientId());
	}

	@Test
	public void testCreateAuthorizationRequestWithDefaultScopes() {
		AuthorizationRequest request = factory.createAuthorizationRequest(Collections.singletonMap("client_id", "foo"));
		assertEquals("[bar]", request.getScope().toString());
	}

}
