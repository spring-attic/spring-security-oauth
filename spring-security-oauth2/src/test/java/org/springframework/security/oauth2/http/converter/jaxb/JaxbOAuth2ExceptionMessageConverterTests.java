/*
 * Copyright 2011-2012 the original author or authors.
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
package org.springframework.security.oauth2.http.converter.jaxb;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
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
@RunWith(PowerMockRunner.class)
@PrepareForTest({ System.class, JaxbOAuth2AccessToken.class })
public class JaxbOAuth2ExceptionMessageConverterTests extends BaseJaxbMessageConverterTest {
	private JaxbOAuth2ExceptionMessageConverter converter;

	private static String DETAILS = "some detail";

	@Before
	public void before() throws Exception {
		converter = new JaxbOAuth2ExceptionMessageConverter();
	}

	@Test
	public void writeInvalidClient() throws IOException {
		OAuth2Exception oauthException = new InvalidClientException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		converter.write(oauthException, contentType, outputMessage);
		assertEquals(expected, getOutput());
	}

	@Test
	public void writeInvalidGrant() throws Exception {
		OAuth2Exception oauthException = new InvalidGrantException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		converter.write(oauthException, contentType, outputMessage);
		assertEquals(expected, getOutput());
	}

	@Test
	public void writeInvalidRequest() throws Exception {
		OAuth2Exception oauthException = new InvalidRequestException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		converter.write(oauthException, contentType, outputMessage);
		assertEquals(expected, getOutput());
	}

	@Test
	public void writeInvalidScope() throws Exception {
		OAuth2Exception oauthException = new InvalidScopeException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		converter.write(oauthException, contentType, outputMessage);
		assertEquals(expected, getOutput());
	}

	@Test
	public void writeUnsupportedGrantType() throws Exception {
		OAuth2Exception oauthException = new UnsupportedGrantTypeException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		converter.write(oauthException, contentType, outputMessage);
		assertEquals(expected, getOutput());
	}

	@Test
	public void writeUnauthorizedClient() throws Exception {
		OAuth2Exception oauthException = new UnauthorizedUserException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		converter.write(oauthException, contentType, outputMessage);
		assertEquals(expected, getOutput());
	}

	@Test
	public void writeAccessDenied() throws Exception {
		OAuth2Exception oauthException = new UserDeniedAuthorizationException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		converter.write(oauthException, contentType, outputMessage);
		assertEquals(expected, getOutput());
	}

	@Test
	public void writeRedirectUriMismatch() throws Exception {
		OAuth2Exception oauthException = new RedirectMismatchException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		converter.write(oauthException, contentType, outputMessage);
		assertEquals(expected, getOutput());
	}

	@Test
	public void writeInvalidToken() throws Exception {
		OAuth2Exception oauthException = new InvalidTokenException(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		converter.write(oauthException, contentType, outputMessage);
		assertEquals(expected, getOutput());
	}

	@Test
	public void writeOAuth2Exception() throws Exception {
		OAuth2Exception oauthException = new OAuth2Exception(DETAILS);
		String expected = createResponse(oauthException.getOAuth2ErrorCode());
		converter.write(oauthException, contentType, outputMessage);
		assertEquals(expected, getOutput());
	}

	// SECOAUTH-311
	@Test
	public void writeCreatesNewUnmarshaller() throws Exception {
		useMockJAXBContext(converter, JaxbOAuth2Exception.class);
		OAuth2Exception oauthException = new OAuth2Exception(DETAILS);

		converter.write(oauthException, contentType, outputMessage);
		verify(context).createMarshaller();

		converter.write(oauthException, contentType, outputMessage);
		verify(context,times(2)).createMarshaller();
	}

	@Test
	public void readInvalidGrant() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_GRANT);
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
		@SuppressWarnings("unused")
		InvalidGrantException result = (InvalidGrantException) converter.read(OAuth2Exception.class, inputMessage);
	}

	@Test
	public void readInvalidRequest() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_REQUEST);
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
		@SuppressWarnings("unused")
		InvalidRequestException result = (InvalidRequestException) converter.read(OAuth2Exception.class, inputMessage);
	}

	@Test
	public void readInvalidScope() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_SCOPE);
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
		@SuppressWarnings("unused")
		InvalidScopeException result = (InvalidScopeException) converter.read(OAuth2Exception.class, inputMessage);
	}

	@Test
	public void readUnsupportedGrantType() throws Exception {
		String accessToken = createResponse(OAuth2Exception.UNSUPPORTED_GRANT_TYPE);
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
		@SuppressWarnings("unused")
		UnsupportedGrantTypeException result = (UnsupportedGrantTypeException) converter.read(OAuth2Exception.class, inputMessage);
	}

	@Test
	public void readUnauthorizedClient() throws Exception {
		String accessToken = createResponse(OAuth2Exception.UNAUTHORIZED_CLIENT);
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
		@SuppressWarnings("unused")
		UnauthorizedUserException result = (UnauthorizedUserException) converter.read(OAuth2Exception.class,
				inputMessage);
	}

	@Test
	public void readAccessDenied() throws Exception {
		String accessToken = createResponse(OAuth2Exception.ACCESS_DENIED);
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
		@SuppressWarnings("unused")
		UserDeniedAuthorizationException result = (UserDeniedAuthorizationException) converter.read(
				OAuth2Exception.class, inputMessage);
	}

	@Test
	public void readRedirectUriMismatch() throws Exception {
		String accessToken = createResponse(OAuth2Exception.REDIRECT_URI_MISMATCH);
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
		@SuppressWarnings("unused")
		RedirectMismatchException result = (RedirectMismatchException) converter.read(OAuth2Exception.class,
				inputMessage);
	}

	@Test
	public void readInvalidToken() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_TOKEN);
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
		@SuppressWarnings("unused")
		InvalidTokenException result = (InvalidTokenException) converter.read(OAuth2Exception.class, inputMessage);
	}

	@Test
	public void readUndefinedException() throws Exception {
		String accessToken = createResponse("notdefinedcode");
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
		@SuppressWarnings("unused")
		OAuth2Exception result = converter.read(OAuth2Exception.class, inputMessage);
	}

	@Test
	public void readInvalidClient() throws IOException {
		String accessToken = createResponse(OAuth2Exception.INVALID_CLIENT);
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
		@SuppressWarnings("unused")
		InvalidClientException result = (InvalidClientException) converter.read(InvalidClientException.class,
				inputMessage);
	}

	// SECOAUTH-311
	@Test
	public void readCreatesNewUnmarshaller() throws Exception {
		useMockJAXBContext(converter, JaxbOAuth2Exception.class);
		String accessToken = createResponse(OAuth2Exception.ACCESS_DENIED);
		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));

		converter.read(OAuth2Exception.class, inputMessage);
		verify(context).createUnmarshaller();

		when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));

		converter.read(OAuth2Exception.class, inputMessage);
		verify(context,times(2)).createUnmarshaller();
	}

	private String createResponse(String error) {
		return "<oauth><error_description>some detail</error_description><error>" + error + "</error></oauth>";
	}
}
