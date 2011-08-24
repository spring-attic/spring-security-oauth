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

import java.io.ByteArrayInputStream;
import java.util.Date;

import org.junit.Test;


/**
 * @author Dave Syer
 *
 */
public class TestDefaultOAuth2SerializationService {
	
	private DefaultOAuth2SerializationService service = new DefaultOAuth2SerializationService();
	
	@Test
	public void testDefaultSerialization() throws Exception {
		OAuth2AccessToken accessToken = new OAuth2AccessToken();
		accessToken.setValue("FOO");
		accessToken.setExpiration(new Date(System.currentTimeMillis()+10000));
		String result = service.serialize(accessToken);
		// System.err.println(result);
		assertTrue("Wrong token: "+result, result.contains("\"token_type\": \"bearer\""));
		assertTrue("Wrong token: "+result, result.contains("\"access_token\": \"FOO\""));
		assertTrue("Wrong token: "+result, result.contains("\"expires_in\":"));
	}

	@Test
	public void testDefaultDeserialization() throws Exception {
		String accessToken = "{\"access_token\": \"FOO\", \"expires_in\": 100, \"token_type\": \"mac\"}";
		OAuth2AccessToken result = service.deserializeJsonAccessToken(new ByteArrayInputStream(accessToken.getBytes()));
		// System.err.println(result);
		assertEquals("FOO", result.getValue());
		assertEquals("mac", result.getTokenType());
		assertTrue(result.getExpiration().getTime()>System.currentTimeMillis());
	}

}
