/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

/**
 * @author Ryan Heaton
 */
public class OAuthCodecTests {

	/**
	 * tests idempotent decode.
	 */
	@Test
	public void testIdempotentDecode() throws Exception {
		String original = "4KaVKEnW6e1a+vwJTpz0VFqIaGU=";
		String encoded = OAuthCodec.oauthEncode(original);
		String decoded = OAuthCodec.oauthDecode(encoded);
		assertEquals(original, decoded);
		decoded = OAuthCodec.oauthDecode(encoded);
		assertEquals(original, decoded);
		decoded = OAuthCodec.oauthDecode(decoded);
		assertFalse(original.equals(decoded));
	}

}
