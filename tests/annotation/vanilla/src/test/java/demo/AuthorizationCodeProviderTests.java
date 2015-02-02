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
package demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.util.LinkedMultiValueMap;

import sparklr.common.AbstractAuthorizationCodeProviderTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes = Application.class)
public class AuthorizationCodeProviderTests extends AbstractAuthorizationCodeProviderTests {
	
	@Test
	@OAuth2ContextConfiguration(resource = MyTrustedClient.class, initialize = false)
	public void testPostToProtectedResource() throws Exception {
		approveAccessTokenGrant("http://anywhere", true);
		assertNotNull(context.getAccessToken());
		LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.set("foo", "bar");
		assertEquals(HttpStatus.CREATED, http.postForStatus("/", form).getStatusCode());
	}

	@Test
	public void testWrongClientIdProvided() throws Exception {
		ResponseEntity<String> response = attemptToGetConfirmationPage("no-such-client", "http://anywhere");
		// With no client id you get an InvalidClientException on the server which is forwarded to /oauth/error
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		String body = response.getBody();
		assertTrue("Wrong body: " + body, body.contains("<html"));
		assertTrue("Wrong body: " + body, body.contains("Bad client credentials"));
	}

	@Test
	public void testWrongClientIdAndOmittedResponseType() throws Exception {
	    // Test wrong client id together with an omitted response_type
	    ResponseEntity<String> response = attemptToGetConfirmationPage("no-such-client", "http://anywhere", null);
	    // With bad client id you get an InvalidClientException on the server which is forwarded to /oauth/error
	    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
	    String body = response.getBody();
	    assertTrue("Wrong body: " + body, body.contains("<html"));
	    assertTrue("Wrong body: " + body, body.contains("Bad client credentials"));
	}

	@Test
	public void testWrongClientIdAndBadResponseTypeProvided() throws Exception {
	    // Test wrong client id together with an omitted response_type
	    ResponseEntity<String> response = attemptToGetConfirmationPage("no-such-client", "http://anywhere", "unsupported");
	    // With bad client id you get an InvalidClientException on the server which is forwarded to /oauth/error
	    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
	    String body = response.getBody();
	    assertTrue("Wrong body: " + body, body.contains("<html"));
	    assertTrue("Wrong body: " + body, body.contains("Bad client credentials"));
	}

}
