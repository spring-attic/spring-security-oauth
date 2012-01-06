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

}
