/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.common;

import java.util.Date;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Dave Syer
 */
class JsonSerializationTests {

    @Test
    void testDefaultSerialization() throws Exception {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
        String result = new ObjectMapper().writeValueAsString(accessToken);
        // System.err.println(result);
        assertTrue(result.contains("\"token_type\":\"bearer\""), "Wrong token: " + result);
        assertTrue(result.contains("\"access_token\":\"FOO\""), "Wrong token: " + result);
        assertTrue(result.contains("\"expires_in\":"), "Wrong token: " + result);
    }

    @Test
    void testRefreshSerialization() throws Exception {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setRefreshToken(new DefaultOAuth2RefreshToken("BAR"));
        accessToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
        String result = new ObjectMapper().writeValueAsString(accessToken);
        // System.err.println(result);
        assertTrue(result.contains("\"token_type\":\"bearer\""), "Wrong token: " + result);
        assertTrue(result.contains("\"access_token\":\"FOO\""), "Wrong token: " + result);
        assertTrue(result.contains("\"refresh_token\":\"BAR\""), "Wrong token: " + result);
        assertTrue(result.contains("\"expires_in\":"), "Wrong token: " + result);
    }

    @Test
    void testExceptionSerialization() throws Exception {
        InvalidClientException exception = new InvalidClientException("FOO");
        exception.addAdditionalInformation("foo", "bar");
        String result = new ObjectMapper().writeValueAsString(exception);
        // System.err.println(result);
        assertTrue(result.contains("\"error\":\"invalid_client\""), "Wrong result: " + result);
        assertTrue(result.contains("\"error_description\":\"FOO\""), "Wrong result: " + result);
        assertTrue(result.contains("\"foo\":\"bar\""), "Wrong result: " + result);
    }

    @Test
    void testDefaultDeserialization() throws Exception {
        String accessToken = "{\"access_token\": \"FOO\", \"expires_in\": 100, \"token_type\": \"mac\"}";
        OAuth2AccessToken result = new ObjectMapper().readValue(accessToken, OAuth2AccessToken.class);
        // System.err.println(result);
        assertEquals("FOO", result.getValue());
        assertEquals("mac", result.getTokenType());
        assertTrue(result.getExpiration().getTime() > System.currentTimeMillis());
    }

    @Test
    void testExceptionDeserialization() throws Exception {
        String exception = "{\"error\": \"invalid_client\", \"error_description\": \"FOO\", \"foo\": \"bar\"}";
        OAuth2Exception result = new ObjectMapper().readValue(exception, OAuth2Exception.class);
        // System.err.println(result);
        assertEquals("FOO", result.getMessage());
        assertEquals("invalid_client", result.getOAuth2ErrorCode());
        assertEquals("{foo=bar}", result.getAdditionalInformation().toString());
        assertTrue(result instanceof InvalidClientException);
    }
}
