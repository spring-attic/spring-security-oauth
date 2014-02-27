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

package org.springframework.security.oauth2.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Date;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * @author Dave Syer
 * 
 */
public class JsonSerializationTests {

	@Test
	public void testDefaultSerialization() throws Exception {
		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
		accessToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
		String result = new ObjectMapper().writeValueAsString(accessToken);
		// System.err.println(result);
		assertTrue("Wrong token: " + result, result.contains("\"token_type\":\"bearer\""));
		assertTrue("Wrong token: " + result, result.contains("\"access_token\":\"FOO\""));
		assertTrue("Wrong token: " + result, result.contains("\"expires_in\":"));
	}

	@Test
	public void testRefreshSerialization() throws Exception {
		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
		accessToken.setRefreshToken(new DefaultOAuth2RefreshToken("BAR"));
		accessToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
		String result = new ObjectMapper().writeValueAsString(accessToken);
		// System.err.println(result);
		assertTrue("Wrong token: " + result, result.contains("\"token_type\":\"bearer\""));
		assertTrue("Wrong token: " + result, result.contains("\"access_token\":\"FOO\""));
		assertTrue("Wrong token: " + result, result.contains("\"refresh_token\":\"BAR\""));
		assertTrue("Wrong token: " + result, result.contains("\"expires_in\":"));
	}

	@Test
	public void testExceptionSerialization() throws Exception {
		InvalidClientException exception = new InvalidClientException("FOO");
		exception.addAdditionalInformation("foo", "bar");
		String result = new ObjectMapper().writeValueAsString(exception);
		// System.err.println(result);
		assertTrue("Wrong result: "+result, result.contains("\"error\":\"invalid_client\""));
		assertTrue("Wrong result: "+result, result.contains("\"error_description\":\"FOO\""));
		assertTrue("Wrong result: "+result, result.contains("\"foo\":\"bar\""));
	}

	@Test
	public void testDefaultDeserialization() throws Exception {
		String accessToken = "{\"access_token\": \"FOO\", \"expires_in\": 100, \"token_type\": \"mac\"}";
		OAuth2AccessToken result = new ObjectMapper().readValue(accessToken, OAuth2AccessToken.class);
		// System.err.println(result);
		assertEquals("FOO", result.getValue());
		assertEquals("mac", result.getTokenType());
		assertTrue(result.getExpiration().getTime() > System.currentTimeMillis());
	}

	@Test
	public void testExceptionDeserialization() throws Exception {
		String exception = "{\"error\": \"invalid_client\", \"error_description\": \"FOO\", \"foo\": \"bar\"}";
		OAuth2Exception result = new ObjectMapper().readValue(exception, OAuth2Exception.class);
		// System.err.println(result);
		assertEquals("FOO", result.getMessage());
		assertEquals("invalid_client", result.getOAuth2ErrorCode());
		assertEquals("{foo=bar}", result.getAdditionalInformation().toString());
		assertTrue(result instanceof InvalidClientException);
	}

}
