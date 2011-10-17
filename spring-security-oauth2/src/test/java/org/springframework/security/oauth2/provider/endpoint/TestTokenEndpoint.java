/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.endpoint;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.easymock.EasyMock;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.TokenGranter;

/**
 * @author Dave Syer
 *
 */
public class TestTokenEndpoint {

	@Test
	public void testGetAccessTokenWithNoClientId() {

		TokenEndpoint endpoint = new TokenEndpoint();
		TokenGranter tokenGranter = EasyMock.createMock(TokenGranter.class);
		endpoint.setTokenGranter(tokenGranter);

		Map<String, String> parameters = new HashMap<String, String>();
		
		tokenGranter.grant("authorization_code", parameters, null, null, new HashSet<String>());
		EasyMock.expectLastCall().andReturn(new OAuth2AccessToken());
		EasyMock.replay(tokenGranter);
		
		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> response = endpoint.getAccessToken("authorization_code", parameters, headers);
		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		String body = response.getBody();
		assertTrue("Wrong body: "+body, body.contains("\"token_type\""));

		EasyMock.verify(tokenGranter);

	}

}
