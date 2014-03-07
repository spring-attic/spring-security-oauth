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


package org.springframework.security.oauth2.client.token.grant.code;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;

/**
 * @author Dave Syer
 *
 */
public class AuthorizationCodeResourceDetailsTests {
	
	private AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();

	@Test
	public void testGetDefaultRedirectUri() {
		details.setPreEstablishedRedirectUri("http://anywhere.com");
		DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setCurrentUri("http://nowhere.com");
		assertEquals("http://nowhere.com", details.getRedirectUri(request));
	}

	@Test
	public void testGetOverrideRedirectUri() {
		details.setPreEstablishedRedirectUri("http://anywhere.com");
		details.setUseCurrentUri(false);
		DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setCurrentUri("http://nowhere.com");
		assertEquals("http://anywhere.com", details.getRedirectUri(request));
	}

}
