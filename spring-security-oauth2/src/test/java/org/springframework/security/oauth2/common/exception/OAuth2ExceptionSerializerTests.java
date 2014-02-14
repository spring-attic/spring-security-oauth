/*
 * Copyright 2011 the original author or authors.
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
package org.springframework.security.oauth2.common.exception;

import static org.junit.Assert.assertEquals;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedUserException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;

/**
 *
 * @author Rob Winch
 *
 */
public class OAuth2ExceptionSerializerTests {

	private static final String DETAILS = "some detail";
	private static ObjectMapper mapper;
	private OAuth2Exception oauthException;

	@BeforeClass
	public static void setUpClass() {
		mapper = new ObjectMapper();
	}

	@After
	public void tearDown() {
		oauthException = null;
	}

	@Test
	public void writeValueAsStringInvalidClient() throws Exception {
		oauthException = new InvalidClientException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void writeValueAsStringInvalidGrant() throws Exception {
		oauthException = new InvalidGrantException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void writeValueAsStringInvalidRequest() throws Exception {
		oauthException = new InvalidRequestException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void writeValueAsStringInvalidScope() throws Exception {
		oauthException = new InvalidScopeException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void writeValueAsStringUnsupportedGrantType() throws Exception {
		oauthException = new UnsupportedGrantTypeException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void writeValueAsStringUnauthorizedClient() throws Exception {
		oauthException = new UnauthorizedUserException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void writeValueAsStringAccessDenied() throws Exception {
		oauthException = new UserDeniedAuthorizationException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void writeValueAsStringRedirectUriMismatch() throws Exception {
		oauthException = new RedirectMismatchException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void writeValueAsStringInvalidToken() throws Exception {
		oauthException = new InvalidTokenException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void writeValueAsStringOAuth2Exception() throws Exception {
		oauthException = new OAuth2Exception(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void writeValueAsStringWithAdditionalDetails() throws Exception {
		oauthException = new InvalidClientException(DETAILS);
		oauthException.addAdditionalInformation("foo", "bar");
		String expected = "{\"error\":\"invalid_client\",\"error_description\":\"some detail\",\"foo\":\"bar\"}";
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	private String createResponse(String error) {
		return "{\"error\":\""+error+"\",\"error_description\":\"some detail\"}";
	}
}
