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
package org.springframework.security.oauth2.client.token.grant.password;

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
public class ResourceOwnerPasswordAccessTokenProviderTests {

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

	private ResourceOwnerPasswordAccessTokenProvider provider = new ResourceOwnerPasswordAccessTokenProvider() {
		@Override
		protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
				MultiValueMap<String, String> form, HttpHeaders headers) {
			params.putAll(form);
			if (!form.containsKey("username") || form.getFirst("username")==null) {
				throw new IllegalArgumentException();
			}
			// Only the map parts of the AccessTokenRequest are sent as form values
			if (form.containsKey("current_uri") || form.containsKey("currentUri")) {
				throw new IllegalArgumentException();
			}
			return new DefaultOAuth2AccessToken("FOO");
		}
	};

	private ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();

	@Test
	public void testGetAccessToken() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		resource.setAccessTokenUri("http://localhost/oauth/token");
		resource.setUsername("foo");
		resource.setPassword("bar");
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
	}

	@Test
	public void testGetAccessTokenWithDynamicCredentials() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.set("username", "foo");
		request.set("password", "bar");
		resource.setAccessTokenUri("http://localhost/oauth/token");
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
	}

	@Test
	public void testCurrentUriNotUsed() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.set("username", "foo");
		request.setCurrentUri("urn:foo:bar");
		resource.setAccessTokenUri("http://localhost/oauth/token");
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
	}

}
