/*
 * Copyright 2011-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.http.converter.jaxb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.common.exceptions.*;

/**
 * @author Rob Winch
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ System.class, JaxbOAuth2AccessToken.class })
class JaxbOAuth2ExceptionMessageConverterTests extends BaseJaxbMessageConverterTest {

    private JaxbOAuth2ExceptionMessageConverter converter;

    private static String DETAILS = "some detail";

    @BeforeEach
    void before() throws Exception {
        converter = new JaxbOAuth2ExceptionMessageConverter();
    }

    @Test
    void writeInvalidClient() throws IOException {
        OAuth2Exception oauthException = new InvalidClientException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        converter.write(oauthException, contentType, outputMessage);
        assertEquals(expected, getOutput());
    }

    @Test
    void writeInvalidGrant() throws Exception {
        OAuth2Exception oauthException = new InvalidGrantException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        converter.write(oauthException, contentType, outputMessage);
        assertEquals(expected, getOutput());
    }

    @Test
    void writeInvalidRequest() throws Exception {
        OAuth2Exception oauthException = new InvalidRequestException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        converter.write(oauthException, contentType, outputMessage);
        assertEquals(expected, getOutput());
    }

    @Test
    void writeInvalidScope() throws Exception {
        OAuth2Exception oauthException = new InvalidScopeException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        converter.write(oauthException, contentType, outputMessage);
        assertEquals(expected, getOutput());
    }

    @Test
    void writeUnsupportedGrantType() throws Exception {
        OAuth2Exception oauthException = new UnsupportedGrantTypeException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        converter.write(oauthException, contentType, outputMessage);
        assertEquals(expected, getOutput());
    }

    @Test
    void writeUnauthorizedClient() throws Exception {
        OAuth2Exception oauthException = new UnauthorizedClientException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        converter.write(oauthException, contentType, outputMessage);
        assertEquals(expected, getOutput());
    }

    @Test
    void writeAccessDenied() throws Exception {
        OAuth2Exception oauthException = new UserDeniedAuthorizationException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        converter.write(oauthException, contentType, outputMessage);
        assertEquals(expected, getOutput());
    }

    @Test
    void writeRedirectUriMismatch() throws Exception {
        OAuth2Exception oauthException = new RedirectMismatchException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        converter.write(oauthException, contentType, outputMessage);
        assertEquals(expected, getOutput());
    }

    @Test
    void writeInvalidToken() throws Exception {
        OAuth2Exception oauthException = new InvalidTokenException(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        converter.write(oauthException, contentType, outputMessage);
        assertEquals(expected, getOutput());
    }

    @Test
    void writeOAuth2Exception() throws Exception {
        OAuth2Exception oauthException = new OAuth2Exception(DETAILS);
        String expected = createResponse(oauthException.getOAuth2ErrorCode());
        converter.write(oauthException, contentType, outputMessage);
        assertEquals(expected, getOutput());
    }

    // SECOAUTH-311
    @Test
    void writeCreatesNewUnmarshaller() throws Exception {
        useMockJAXBContext(converter, JaxbOAuth2Exception.class);
        OAuth2Exception oauthException = new OAuth2Exception(DETAILS);
        converter.write(oauthException, contentType, outputMessage);
        verify(context).createMarshaller();
        converter.write(oauthException, contentType, outputMessage);
        verify(context, times(2)).createMarshaller();
    }

    @Test
    void readInvalidGrant() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_GRANT);
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        @SuppressWarnings("unused")
        InvalidGrantException result = (InvalidGrantException) converter.read(OAuth2Exception.class, inputMessage);
    }

    @Test
    void readInvalidRequest() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_REQUEST);
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        @SuppressWarnings("unused")
        InvalidRequestException result = (InvalidRequestException) converter.read(OAuth2Exception.class, inputMessage);
    }

    @Test
    void readInvalidScope() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_SCOPE);
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        @SuppressWarnings("unused")
        InvalidScopeException result = (InvalidScopeException) converter.read(OAuth2Exception.class, inputMessage);
    }

    @Test
    void readUnsupportedGrantType() throws Exception {
        String accessToken = createResponse(OAuth2Exception.UNSUPPORTED_GRANT_TYPE);
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        @SuppressWarnings("unused")
        UnsupportedGrantTypeException result = (UnsupportedGrantTypeException) converter.read(OAuth2Exception.class, inputMessage);
    }

    @Test
    void readUnauthorizedClient() throws Exception {
        String accessToken = createResponse(OAuth2Exception.UNAUTHORIZED_CLIENT);
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        @SuppressWarnings("unused")
        UnauthorizedClientException result = (UnauthorizedClientException) converter.read(OAuth2Exception.class, inputMessage);
    }

    @Test
    void readAccessDenied() throws Exception {
        String accessToken = createResponse(OAuth2Exception.ACCESS_DENIED);
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        @SuppressWarnings("unused")
        UserDeniedAuthorizationException result = (UserDeniedAuthorizationException) converter.read(OAuth2Exception.class, inputMessage);
    }

    @Test
    void readRedirectUriMismatch() throws Exception {
        String accessToken = createResponse(OAuth2Exception.REDIRECT_URI_MISMATCH);
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        @SuppressWarnings("unused")
        RedirectMismatchException result = (RedirectMismatchException) converter.read(OAuth2Exception.class, inputMessage);
    }

    @Test
    void readInvalidToken() throws Exception {
        String accessToken = createResponse(OAuth2Exception.INVALID_TOKEN);
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        @SuppressWarnings("unused")
        InvalidTokenException result = (InvalidTokenException) converter.read(OAuth2Exception.class, inputMessage);
    }

    @Test
    void readUndefinedException() throws Exception {
        String accessToken = createResponse("notdefinedcode");
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        @SuppressWarnings("unused")
        OAuth2Exception result = converter.read(OAuth2Exception.class, inputMessage);
    }

    @Test
    void readInvalidClient() throws IOException {
        String accessToken = createResponse(OAuth2Exception.INVALID_CLIENT);
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        @SuppressWarnings("unused")
        InvalidClientException result = (InvalidClientException) converter.read(InvalidClientException.class, inputMessage);
    }

    // SECOAUTH-311
    @Test
    void readCreatesNewUnmarshaller() throws Exception {
        useMockJAXBContext(converter, JaxbOAuth2Exception.class);
        String accessToken = createResponse(OAuth2Exception.ACCESS_DENIED);
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        converter.read(OAuth2Exception.class, inputMessage);
        verify(context).createUnmarshaller();
        when(inputMessage.getBody()).thenReturn(createInputStream(accessToken));
        converter.read(OAuth2Exception.class, inputMessage);
        verify(context, times(2)).createUnmarshaller();
    }

    private String createResponse(String error) {
        return "<oauth><error_description>some detail</error_description><error>" + error + "</error></oauth>";
    }
}
