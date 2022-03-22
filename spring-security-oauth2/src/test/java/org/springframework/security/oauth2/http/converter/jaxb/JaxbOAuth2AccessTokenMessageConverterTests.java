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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.IOException;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;

/**
 * @author Rob Winch
 */
@PrepareForTest(JaxbOAuth2AccessToken.class)
class JaxbOAuth2AccessTokenMessageConverterTests extends BaseJaxbMessageConverterTest {

    private JaxbOAuth2AccessTokenMessageConverter converter;

    private DefaultOAuth2AccessToken accessToken;

    @BeforeEach
    void before() throws Exception {
        converter = new JaxbOAuth2AccessTokenMessageConverter();
        accessToken = new DefaultOAuth2AccessToken("SlAV32hkKG");
        accessToken.setExpiration(expiration);
        accessToken.setRefreshToken(new DefaultOAuth2RefreshToken("8xLOxBtZp8"));
    }

    @Test
    void writeAccessToken() throws IOException {
        converter.write(accessToken, contentType, outputMessage);
        assertEquals(OAUTH_ACCESSTOKEN, getOutput());
    }

    @Test
    void writeAccessTokenNoRefresh() throws IOException {
        accessToken.setRefreshToken(null);
        converter.write(accessToken, contentType, outputMessage);
        assertEquals(OAUTH_ACCESSTOKEN_NOREFRESH, getOutput());
    }

    @Test
    void writeAccessTokenNoExpires() throws IOException {
        accessToken.setRefreshToken(null);
        accessToken.setExpiration(null);
        converter.write(accessToken, contentType, outputMessage);
        assertEquals(OAUTH_ACCESSTOKEN_NOEXPIRES, getOutput());
    }

    // SECOAUTH-311
    @Test
    void writeCreatesNewMarshaller() throws Exception {
        useMockJAXBContext(converter, JaxbOAuth2AccessToken.class);
        when(inputMessage.getBody()).thenReturn(createInputStream(OAUTH_ACCESSTOKEN));
        converter.write(accessToken, contentType, outputMessage);
        verify(context).createMarshaller();
        converter.write(accessToken, contentType, outputMessage);
        verify(context, times(2)).createMarshaller();
    }

    @Test
    void readAccessToken() throws IOException {
        when(inputMessage.getBody()).thenReturn(createInputStream(OAUTH_ACCESSTOKEN));
        OAuth2AccessToken token = converter.read(OAuth2AccessToken.class, inputMessage);
        assertTokenEquals(accessToken, token);
    }

    @Test
    void readAccessTokenNoRefresh() throws IOException {
        accessToken.setRefreshToken(null);
        when(inputMessage.getBody()).thenReturn(createInputStream(OAUTH_ACCESSTOKEN_NOREFRESH));
        OAuth2AccessToken token = converter.read(OAuth2AccessToken.class, inputMessage);
        assertTokenEquals(accessToken, token);
    }

    @Test
    void readAccessTokenNoExpires() throws IOException {
        accessToken.setRefreshToken(null);
        accessToken.setExpiration(null);
        when(inputMessage.getBody()).thenReturn(createInputStream(OAUTH_ACCESSTOKEN_NOEXPIRES));
        OAuth2AccessToken token = converter.read(OAuth2AccessToken.class, inputMessage);
        assertTokenEquals(accessToken, token);
    }

    // SECOAUTH-311
    @Test
    void readCreatesNewUnmarshaller() throws Exception {
        useMockJAXBContext(converter, JaxbOAuth2AccessToken.class);
        when(inputMessage.getBody()).thenReturn(createInputStream(OAUTH_ACCESSTOKEN));
        converter.read(OAuth2AccessToken.class, inputMessage);
        verify(context).createUnmarshaller();
        when(inputMessage.getBody()).thenReturn(createInputStream(OAUTH_ACCESSTOKEN));
        converter.read(OAuth2AccessToken.class, inputMessage);
        verify(context, times(2)).createUnmarshaller();
    }

    private static void assertTokenEquals(OAuth2AccessToken expected, OAuth2AccessToken actual) {
        assertEquals(expected.getTokenType(), actual.getTokenType());
        assertEquals(expected.getValue(), actual.getValue());
        OAuth2RefreshToken expectedRefreshToken = expected.getRefreshToken();
        if (expectedRefreshToken == null) {
            assertNull(actual.getRefreshToken());
        } else {
            assertEquals(expectedRefreshToken.getValue(), actual.getRefreshToken().getValue());
        }
        assertEquals(expected.getScope(), actual.getScope());
        Date expectedExpiration = expected.getExpiration();
        if (expectedExpiration == null) {
            assertNull(actual.getExpiration());
        } else {
            assertEquals(expectedExpiration.getTime(), actual.getExpiration().getTime());
        }
    }
}
