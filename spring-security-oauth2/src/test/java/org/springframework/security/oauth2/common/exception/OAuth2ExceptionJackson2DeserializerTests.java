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

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
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

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 *
 * @author Rob Winch
 * @author Dave Syer
 *
 */
public class OAuth2ExceptionJackson2DeserializerTests {
	private static final String DETAILS = "some detail";
	private static ObjectMapper mapper;

	@BeforeClass
	public static void setUpClass() {
		mapper = new ObjectMapper();
	}

	@Test
	public void readValueInvalidGrant() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_GRANT);
		InvalidGrantException result = (InvalidGrantException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueInvalidRequest() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_REQUEST);
		InvalidRequestException result = (InvalidRequestException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueInvalidScope() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_SCOPE);
		InvalidScopeException result = (InvalidScopeException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueIsufficientScope() throws Exception {
		String accessToken = "{\"error\": \"insufficient_scope\", \"error_description\": \"insufficient scope\", \"scope\": \"bar foo\"}";
		InsufficientScopeException result = (InsufficientScopeException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals("insufficient scope",result.getMessage());
		assertEquals("bar foo",result.getAdditionalInformation().get("scope").toString());
	}

	@Test
	public void readValueUnsupportedGrantType() throws Exception {
		String accessToken = createResponse(OAuth2Exception.UNSUPPORTED_GRANT_TYPE);
		UnsupportedGrantTypeException result = (UnsupportedGrantTypeException) mapper.readValue(accessToken,
				OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueUnauthorizedClient() throws Exception {
		String accessToken = createResponse(OAuth2Exception.UNAUTHORIZED_CLIENT);
		UnauthorizedUserException result = (UnauthorizedUserException) mapper.readValue(accessToken,
				OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueAccessDenied() throws Exception {
		String accessToken = createResponse(OAuth2Exception.ACCESS_DENIED);
		UserDeniedAuthorizationException result = (UserDeniedAuthorizationException) mapper.readValue(accessToken,
				OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueRedirectUriMismatch() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_GRANT, "Redirect URI mismatch.");
		RedirectMismatchException result = (RedirectMismatchException) mapper.readValue(accessToken,
				OAuth2Exception.class);
		assertEquals("Redirect URI mismatch.",result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueInvalidToken() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_TOKEN);
		InvalidTokenException result = (InvalidTokenException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueUndefinedException() throws Exception {
		String accessToken = createResponse("notdefinedcode");
		OAuth2Exception result = mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueInvalidClient() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_CLIENT);
		InvalidClientException result = (InvalidClientException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueWithAdditionalDetails() throws Exception {
		String accessToken = "{\"error\": \"invalid_client\", \"error_description\": \"some detail\", \"foo\": \"bar\"}";
		InvalidClientException result = (InvalidClientException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals("{foo=bar}",result.getAdditionalInformation().toString());
	}

	@Test
	public void readValueWithObjects() throws Exception {
		String accessToken = "{\"error\": [\"invalid\",\"client\"], \"error_description\": {\"some\":\"detail\"}, \"foo\": [\"bar\"]}";
		OAuth2Exception result = mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals("{some=detail}",result.getMessage());
		assertEquals("{foo=[bar]}",result.getAdditionalInformation().toString());
	}

	private String createResponse(String error, String message) {
		return "{\"error\":\"" + error + "\",\"error_description\":\""+message+"\"}";
	}

	private String createResponse(String error) {
		return createResponse(error, DETAILS);
	}

}
