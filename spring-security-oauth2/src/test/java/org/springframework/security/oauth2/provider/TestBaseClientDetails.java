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

package org.springframework.security.oauth2.provider;

import static org.junit.Assert.*;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;

/**
 * @author Dave Syer
 * 
 */
public class TestBaseClientDetails {

	/**
	 * test default constructor
	 */
	@Test
	public void testBaseClientDetailsDefaultConstructor() {
		BaseClientDetails details = new BaseClientDetails();
		assertEquals("[]", details.getResourceIds().toString());
		assertEquals("[]", details.getScope().toString());
		assertEquals("[]", details.getAuthorizedGrantTypes().toString());
		assertEquals("[]", details.getAuthorities().toString());
	}

	/**
	 * test explicit convenience constructor
	 */
	@Test
	public void testBaseClientDetailsConvenienceConstructor() {
		BaseClientDetails details = new BaseClientDetails("", "foo,bar", "authorization_code", "ROLE_USER");
		assertEquals("[]", details.getResourceIds().toString());
		assertEquals("[bar, foo]", details.getScope().toString());
		assertEquals("[authorization_code]", details.getAuthorizedGrantTypes().toString());
		assertEquals("[ROLE_USER]", details.getAuthorities().toString());
	}

	@Test
	public void testJsonSerialize() throws Exception {
		BaseClientDetails details = new BaseClientDetails("", "foo,bar", "authorization_code", "ROLE_USER");
		details.setClientId("foo");
		details.setClientSecret("bar");
		String value = new ObjectMapper().writeValueAsString(details);
		assertTrue(value.contains("client_id"));
		assertTrue(value.contains("client_secret"));
		assertTrue(value.contains("authorized_grant_types"));
		assertTrue(value.contains("[\"ROLE_USER\"]"));
	}

	@Test
	public void testJsonDeserialize() throws Exception {
		String value = "{\"foo\":\"bar\",\"scope\":[\"bar\",\"foo\"],\"authorized_grant_types\":[\"authorization_code\"],\"access_token_validity\":0,\"authorities\":[\"ROLE_USER\"]}";
		BaseClientDetails details = new ObjectMapper().readValue(value, BaseClientDetails.class);
		// System.err.println(new ObjectMapper().writeValueAsString(details));
		BaseClientDetails expected = new BaseClientDetails("", "foo,bar", "authorization_code", "ROLE_USER");
		assertEquals(expected, details);
	}
}
