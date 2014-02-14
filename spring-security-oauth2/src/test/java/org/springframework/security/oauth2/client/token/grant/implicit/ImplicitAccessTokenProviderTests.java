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
package org.springframework.security.oauth2.client.token.grant.implicit;

import static org.junit.Assert.assertEquals;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 * 
 */
public class ImplicitAccessTokenProviderTests {

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

	private ImplicitAccessTokenProvider provider = new ImplicitAccessTokenProvider() {
		@Override
		protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
				MultiValueMap<String, String> form, HttpHeaders headers) {
			params.putAll(form);
			return new DefaultOAuth2AccessToken("FOO");
		}
	};

	private ImplicitResourceDetails resource = new ImplicitResourceDetails();

	@Test(expected = IllegalStateException.class)
	public void testRedirectNotSpecified() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		provider.obtainAccessToken(resource, request);
	}

	@Test
	public void testGetAccessTokenRequest() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		resource.setClientId("foo");
		resource.setAccessTokenUri("http://localhost/oauth/authorize");
		resource.setPreEstablishedRedirectUri("http://anywhere.com");
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
		assertEquals("foo", params.getFirst("client_id"));
		assertEquals("token", params.getFirst("response_type"));
		assertEquals("http://anywhere.com", params.getFirst("redirect_uri"));
	}

}
