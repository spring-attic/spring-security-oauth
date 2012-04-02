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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;

/**
 * @author Dave Syer
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class TestTokenEndpoint {
	@Mock
	private TokenGranter tokenGranter;

	@Test
	public void testGetAccessTokenWithNoClientId() {
/*
		TokenEndpoint endpoint = new TokenEndpoint();
		endpoint.setTokenGranter(tokenGranter);

		Map<String, String> parameters = new HashMap<String, String>();

		OAuth2AccessToken expectedToken = new OAuth2AccessToken("FOO");
		when(tokenGranter.grant("authorization_code", parameters, "", new HashSet<String>())).thenReturn(expectedToken);

		Model model = new ExtendedModelMap();
		
		String response = endpoint.getAccessToken(new UsernamePasswordAuthenticationToken(null, null,
				Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT"))), "authorization_code", parameters, model);

		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		OAuth2AccessToken body = response.getBody();
		assertEquals(body,expectedToken);
		assertTrue("Wrong body: " + body, body.getTokenType()!=null);
*/
		
	}
}
