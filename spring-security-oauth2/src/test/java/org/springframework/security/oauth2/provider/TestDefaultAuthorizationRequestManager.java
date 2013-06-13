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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

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


  @Test
  public void testCreateAuthorizationRequesForAuthorizationCode() {
    Map<String, String> requestParameters = new HashMap<String, String>();
    requestParameters.put("client_id", "foo");
    requestParameters.put("grant_type", "authorization_code");
    requestParameters.put("code", "XXXXXXX");
    requestParameters.put("scope", "bar2");

    AuthorizationRequest request = factory.createAuthorizationRequest(requestParameters);
    assertEquals("foo", request.getClientId());
    //The scope must be empty
    assertEquals("[]", request.getScope().toString());
  }

  @Test
  public void testCreateAuthorizationRequestForRefeshToken() {
    Map<String, String> requestParameters = new HashMap<String, String>();
    requestParameters.put("client_id", "foo");
    requestParameters.put("grant_type", "refresh_token");
    requestParameters.put("refresh_token", "XXXXXXX");
    requestParameters.put("scope", "bar2");

    AuthorizationRequest request = factory.createAuthorizationRequest(requestParameters);
    assertEquals("foo", request.getClientId());
    //The scope must be equals to scope param
    assertEquals("[bar2]", request.getScope().toString());
  }

}
