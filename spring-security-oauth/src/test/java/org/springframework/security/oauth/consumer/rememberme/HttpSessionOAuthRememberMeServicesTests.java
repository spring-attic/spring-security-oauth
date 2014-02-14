/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.consumer.rememberme;

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth.consumer.OAuthConsumerToken;

/**
 * @author Alex Rau
 */
public class HttpSessionOAuthRememberMeServicesTests {

	@Test
	public void testEmptySession() {

		MockHttpSession mockHttpSession = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		request.setSession(mockHttpSession);

		HttpSessionOAuthRememberMeServices oAuthRememberMeService = new HttpSessionOAuthRememberMeServices();

		Map<String, OAuthConsumerToken> tokens = oAuthRememberMeService.loadRememberedTokens(request, response);

		Assert.assertNull(tokens);

	}

	@Test
	public void testNoTokensRemembered() {

		MockHttpSession mockHttpSession = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		request.setSession(mockHttpSession);

		HttpSessionOAuthRememberMeServices oAuthRememberMeService = new HttpSessionOAuthRememberMeServices();

		Map<String, OAuthConsumerToken> tokens = new HashMap<String, OAuthConsumerToken>();

		oAuthRememberMeService.rememberTokens(tokens, request, response);

		Assert.assertEquals(0, oAuthRememberMeService.loadRememberedTokens(request, response).size());

	}

	@Test
	public void testStoreEverything() {

		MockHttpSession mockHttpSession = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		request.setSession(mockHttpSession);

		HttpSessionOAuthRememberMeServices oAuthRememberMeService = new HttpSessionOAuthRememberMeServices();

		Map<String, OAuthConsumerToken> tokens = new HashMap<String, OAuthConsumerToken>();

		{
			OAuthConsumerToken token = new OAuthConsumerToken();
			token.setAccessToken(false);
			tokens.put("resourceID1", token);
		}

		{
			OAuthConsumerToken token = new OAuthConsumerToken();
			token.setAccessToken(true);
			tokens.put("resourceID2", token);
		}

		oAuthRememberMeService.rememberTokens(tokens, request, response);

		Assert.assertEquals(1, oAuthRememberMeService.loadRememberedTokens(request, response).size());

	}

	@Test
	public void testStoreRequestTokensOnly() {

		MockHttpSession mockHttpSession = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		request.setSession(mockHttpSession);

		HttpSessionOAuthRememberMeServices oAuthRememberMeService = new HttpSessionOAuthRememberMeServices();

		Map<String, OAuthConsumerToken> tokens = new HashMap<String, OAuthConsumerToken>();

		{
			OAuthConsumerToken token = new OAuthConsumerToken();
			token.setAccessToken(false);
			tokens.put("resourceID1", token);
		}

		{
			OAuthConsumerToken token = new OAuthConsumerToken();
			token.setAccessToken(true);
			tokens.put("resourceID2", token);
		}

		oAuthRememberMeService.rememberTokens(tokens, request, response);

		Map<String, OAuthConsumerToken> storedTokens = oAuthRememberMeService.loadRememberedTokens(request, response);

		Assert.assertEquals(1, storedTokens.size());

		Assert.assertNotNull(storedTokens.get("resourceID1"));

	}

}
