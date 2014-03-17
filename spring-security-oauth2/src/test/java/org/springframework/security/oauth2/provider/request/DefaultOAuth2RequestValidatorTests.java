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

package org.springframework.security.oauth2.provider.request;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

/**
 * @author Dave Syer
 *
 */
public class DefaultOAuth2RequestValidatorTests {
	
	private DefaultOAuth2RequestValidator validator = new DefaultOAuth2RequestValidator();

	private BaseClientDetails client = new BaseClientDetails();

	private DefaultOAuth2RequestFactory factory = new DefaultOAuth2RequestFactory(new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return client;
		}
	});

	private Map<String, String> params;

	@Before
	public void start() {
		client.setClientId("foo");
		client.setScope(Collections.singleton("bar"));
		params = new HashMap<String, String>();
		params.put("client_id", "foo");
		params.put("scope", "foo");
	}

	@Test(expected=InvalidScopeException.class)
	public void testNotPermittedForEmpty() {
		AuthorizationRequest request = factory.createAuthorizationRequest(params);
		request.setScope(Collections.<String>emptySet());
		validator.validateScope(request, client);;
	}

	@Test(expected=InvalidScopeException.class)
	public void testNotPermittedForAuthorization() {
		AuthorizationRequest request = factory.createAuthorizationRequest(params );
		request.setScope(Collections.singleton("foo"));
		validator.validateScope(request, client);
	}

	@Test(expected=InvalidScopeException.class)
	public void testNotPermittedForScope() {
		AuthorizationRequest request = factory.createAuthorizationRequest(params );
		TokenRequest tokenRequest = factory.createTokenRequest(request, "authorization_code");
		tokenRequest.setScope(Collections.singleton("foo"));
		validator.validateScope(tokenRequest, client);;
	}

}
