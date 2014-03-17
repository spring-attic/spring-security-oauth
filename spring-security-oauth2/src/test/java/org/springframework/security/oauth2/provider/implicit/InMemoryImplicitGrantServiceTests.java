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

package org.springframework.security.oauth2.provider.implicit;

import static org.junit.Assert.assertEquals;

import java.util.Collections;

import org.junit.Test;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

/**
 * @author Dave Syer
 * 
 */
public class InMemoryImplicitGrantServiceTests {

	private InMemoryImplicitGrantService service = new InMemoryImplicitGrantService();

	private TokenRequest tokenRequest = new TokenRequest(Collections.<String, String> emptyMap(), "client", Collections.singleton("read"), "implicit");

	private ClientDetails client = new BaseClientDetails("client", "resource", "read", "implicit", "ROLE_CLIENT");

	private OAuth2Request oauth2Request = tokenRequest.createOAuth2Request(client );

	@Test
	public void testBasicInOut() {
		service.store(oauth2Request, tokenRequest);
		assertEquals(oauth2Request, service.remove(tokenRequest));
		assertEquals(null, service.remove(tokenRequest));
	}

	@Test
	public void testTransformedRequest() {
		service.store(oauth2Request, tokenRequest);
		TokenRequest tokenRequest = new TokenRequest(Collections.<String, String> emptyMap(), "client", Collections.singleton("read"), "implicit");
		assertEquals(oauth2Request, service.remove(tokenRequest));
		assertEquals(null, service.remove(tokenRequest));
	}

}
