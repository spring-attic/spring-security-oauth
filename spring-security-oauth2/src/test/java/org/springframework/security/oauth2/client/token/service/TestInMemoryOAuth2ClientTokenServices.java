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
package org.springframework.security.oauth2.client.token.service;

import static org.junit.Assert.assertNotNull;

import java.util.Arrays;

import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Dave Syer
 * 
 */
public class TestInMemoryOAuth2ClientTokenServices {

	private InMemoryOAuth2ClientTokenServices services = new InMemoryOAuth2ClientTokenServices();
	private BaseOAuth2ProtectedResourceDetails resource;
	
	public TestInMemoryOAuth2ClientTokenServices() {
		resource = new BaseOAuth2ProtectedResourceDetails();
		resource.setId("resource");
	}

	@Test
	public void testNonNullAuthentication() {
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("foo", "bar",
				Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
		services.storeToken(authentication, resource, new OAuth2AccessToken("FOO"));
		OAuth2AccessToken token = services.getToken(authentication, resource);
		assertNotNull(token);
	}

	@Test
	public void testNullAuthentication() {
		services.storeToken(null, resource, new OAuth2AccessToken("FOO"));
		OAuth2AccessToken token = services.getToken(null, resource);
		assertNotNull(token);
	}

}
