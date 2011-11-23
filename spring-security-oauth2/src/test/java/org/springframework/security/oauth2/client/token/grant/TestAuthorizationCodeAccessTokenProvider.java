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
package org.springframework.security.oauth2.client.token.grant;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * @author Dave Syer
 *
 */
public class TestAuthorizationCodeAccessTokenProvider {
	
	@Rule
	public ExpectedException expected = ExpectedException.none();

	private AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider() {
		protected org.springframework.web.client.RestTemplate getRestTemplate() {
			return new RestTemplate() {
				@SuppressWarnings("unchecked")
				public <T extends Object> T execute(String url, HttpMethod method, RequestCallback requestCallback, ResponseExtractor<T> responseExtractor, Map<String,?> urlVariables) throws RestClientException {
					return (T) new OAuth2AccessToken("FOO");
				};
			};
		}
	};
	private AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
	
	@Test
	public void testGetAccessToken() throws Exception {
		AccessTokenRequest request = new AccessTokenRequest();
		request.setAuthorizationCode("foo");
		resource.setAccessTokenUri("http://localhost/oauth/token");
		assertEquals("FOO", provider.obtainNewAccessToken(resource , request).getValue());
	}

	@Test
	public void testRedirectToAuthorizationEndpoint() throws Exception {
		AccessTokenRequest request = new AccessTokenRequest();
		request.setUserAuthorizationRedirectUri("/come/back/soon");
		resource.setUserAuthorizationUri("http://localhost/oauth/authorize");
		try {
			provider.obtainNewAccessToken(resource , request);
			fail("Expected UserRedirectRequiredException");
		} catch (UserRedirectRequiredException e) {
			assertEquals("http://localhost/oauth/authorize", e.getRedirectUri());
			assertEquals("/come/back/soon", e.getStateToPreserve());
		}
	}

}
