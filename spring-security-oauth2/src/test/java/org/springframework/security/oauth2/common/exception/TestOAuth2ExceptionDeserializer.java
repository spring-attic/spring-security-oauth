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

import org.codehaus.jackson.map.ObjectMapper;
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

@SuppressWarnings("unused")
public class TestOAuth2ExceptionDeserializer  {

	private static ObjectMapper mapper;

	@BeforeClass
	public static void setUpClass() {
		mapper = new ObjectMapper();
	}

	@Test
	public void deserializeInvalidGrant() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_GRANT);
		InvalidGrantException result = (InvalidGrantException) mapper.readValue(accessToken, OAuth2Exception.class);
	}

	@Test
	public void deserializeInvalidRequest() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_REQUEST);
		InvalidRequestException result = (InvalidRequestException) mapper.readValue(accessToken, OAuth2Exception.class);
	}

	@Test
	public void deserializeInvalidScope() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_SCOPE);
		InvalidScopeException result = (InvalidScopeException) mapper.readValue(accessToken, OAuth2Exception.class);
	}

	@Test
	public void deserializeUnsupportedGrantType() throws Exception {
		String accessToken = createResponse(OAuth2Exception.UNSUPPORTED_GRANT_TYPE);
		UnsupportedGrantTypeException result = (UnsupportedGrantTypeException) mapper.readValue(accessToken, OAuth2Exception.class);
	}

	@Test
	public void deserializeUnauthorizedClient() throws Exception {
		String accessToken = createResponse(OAuth2Exception.UNAUTHORIZED_CLIENT);
		UnauthorizedClientException result = (UnauthorizedClientException) mapper.readValue(accessToken, OAuth2Exception.class);
	}

	@Test
	public void deserializeAccessDenied() throws Exception {
		String accessToken = createResponse(OAuth2Exception.ACCESS_DENIED);
		UserDeniedAuthorizationException result = (UserDeniedAuthorizationException) mapper.readValue(accessToken, OAuth2Exception.class);
	}

	@Test
	public void deserializeRedirectUriMismatch() throws Exception {
		String accessToken = createResponse(OAuth2Exception.REDIRECT_URI_MISMATCH);
		RedirectMismatchException result = (RedirectMismatchException)mapper.readValue(accessToken, OAuth2Exception.class);
	}

	@Test
	public void deserializeInvalidToken() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_TOKEN);
		InvalidTokenException result = (InvalidTokenException) mapper.readValue(accessToken, OAuth2Exception.class);
	}

	@Test
	public void deserializeUndefinedException() throws Exception {
		String accessToken = createResponse("notdefinedcode");
		OAuth2Exception result = mapper.readValue(accessToken, OAuth2Exception.class);
	}

	@Test
	public void deserializeInvalidClient() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_CLIENT);
		InvalidClientException result = (InvalidClientException) mapper.readValue(accessToken, OAuth2Exception.class);
	}

	private String createResponse(String error) {
		return "{\"error\":\""+error+"\",\"error_description\":\"some detail\"}";
	}

}
