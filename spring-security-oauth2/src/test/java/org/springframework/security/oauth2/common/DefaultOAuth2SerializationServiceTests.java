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

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * @author Dave Syer
 * 
 */
public class DefaultOAuth2SerializationServiceTests {

	@Test
	public void testDefaultDeserialization() throws Exception {
		Map<String, String> accessToken = MapBuilder.create("access_token", "FOO").add("expires_in", "100")
				.add("token_type", "mac").build();
		OAuth2AccessToken result = DefaultOAuth2AccessToken.valueOf(accessToken);
		// System.err.println(result);
		assertEquals("FOO", result.getValue());
		assertEquals("mac", result.getTokenType());
		assertTrue(result.getExpiration().getTime() > System.currentTimeMillis());
	}

	@Test
	public void testExceptionDeserialization() throws Exception {
		Map<String, String> exception = MapBuilder.create("error", "invalid_client").add("error_description", "FOO")
				.build();
		OAuth2Exception result = OAuth2Exception.valueOf(exception);
		// System.err.println(result);
		assertEquals("FOO", result.getMessage());
		assertEquals("invalid_client", result.getOAuth2ErrorCode());
		assertTrue(result instanceof InvalidClientException);
	}

	private static class MapBuilder {

		private HashMap<String, String> map = new HashMap<String, String>();

		private MapBuilder(String key, String value) {
			map.put(key, value);
		}

		public static MapBuilder create(String key, String value) {
			return new MapBuilder(key, value);
		}

		public MapBuilder add(String key, String value) {
			map.put(key, value);
			return this;
		}

		public Map<String, String> build() {
			return map;
		}
	}

}
