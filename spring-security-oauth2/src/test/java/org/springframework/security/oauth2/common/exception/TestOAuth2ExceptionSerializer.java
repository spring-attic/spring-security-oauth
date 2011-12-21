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
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;

public class TestOAuth2ExceptionSerializer {

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
	public void serializeInvalidClient() throws Exception {
		oauthException = new InvalidClientException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void serializeInvalidGrant() throws Exception {
		oauthException = new InvalidGrantException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void serializeInvalidRequest() throws Exception {
		oauthException = new InvalidRequestException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void serializeInvalidScope() throws Exception {
		oauthException = new InvalidScopeException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void serializeUnsupportedGrantType() throws Exception {
		oauthException = new UnsupportedGrantTypeException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void serializeUnauthorizedClient() throws Exception {
		oauthException = new UnauthorizedClientException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void serializeAccessDenied() throws Exception {
		oauthException = new UserDeniedAuthorizationException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void serializeRedirectUriMismatch() throws Exception {
		oauthException = new RedirectMismatchException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void serializeInvalidToken() throws Exception {
		oauthException = new InvalidTokenException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	@Test
	public void serializeOAuth2Exception() throws Exception {
		oauthException = new OAuth2Exception(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		assertEquals(expected,mapper.writeValueAsString(oauthException));
	}

	private String createResponse(String error) {
		return "{\"error\":\""+error+"\",\"error_description\":\"some detail\"}";
	}
}
