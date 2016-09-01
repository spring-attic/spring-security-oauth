/*
 * Copyright 2013-2014 the original author or authors.
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

package org.springframework.security.oauth2.provider.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.util.SerializationUtils;

/**
 * @author Dave Syer
 *
 */
public class OAuth2AuthenticationDetailsTests {

	@Test
	public void testSerializationWithDetails() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, "FOO");
		request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, "bearer");
		OAuth2AuthenticationDetails holder = new OAuth2AuthenticationDetails(request);
		OAuth2AuthenticationDetails other = (OAuth2AuthenticationDetails) SerializationUtils.deserialize(SerializationUtils
				.serialize(holder));
		assertEquals(holder, other);
	}

	@Test
	public void testToString() {
		assertEquals("", new OAuth2AuthenticationDetails(mock()).toString());
		assertEquals("tokenValue=<TOKEN>", new OAuth2AuthenticationDetails(mock(
						null, null, null, null, "FOO")).toString());
		assertEquals("tokenType=bearer", new OAuth2AuthenticationDetails(mock(
						null, null, null, null, null, "bearer")).toString());
		assertEquals("tokenType=bearer, tokenValue=<TOKEN>", new OAuth2AuthenticationDetails(mock(
						null, null, null, null, "FOO", "bearer")).toString());
		assertEquals("remoteAddress=127.0.0.1, sessionId=<SESSION>, tokenType=bearer, tokenValue=<TOKEN>",
						new OAuth2AuthenticationDetails(mock(
										null, null, new MockHttpSession(), "127.0.0.1", "FOO", "bearer")).toString());
		assertEquals("remoteAddress=127.0.0.1, sessionId=<SESSION>, tokenType=bearer, tokenValue=<TOKEN>, "
						+ "method=GET, requestURI=/foo/bar", new OAuth2AuthenticationDetails(mock("GET", "/foo/bar",
						new MockHttpSession(), "127.0.0.1", "FOO", "bearer")).toString());
	}

	@Test
	public void testHashCode() {
		assertEquals(31*31*31*31*31, new OAuth2AuthenticationDetails(mock()).hashCode());
		assertEquals(31*(31*31*31*31 + "GET".hashCode()) + "/foo/bar".hashCode(),
						new OAuth2AuthenticationDetails(mock("GET", "/foo/bar")).hashCode());
	}

	@Test
	public void testEquals() {
		OAuth2AuthenticationDetails details = new OAuth2AuthenticationDetails(mock("GET", "/foo/bar"));
		assertEquals(details, new OAuth2AuthenticationDetails(mock("GET", "/foo/bar")));
		assertNotEquals(details, new OAuth2AuthenticationDetails(mock("GET", "/bar/foo")));
	}

	@Test
	public void testGetMethod() {
		assertNull(new OAuth2AuthenticationDetails(mock()).getMethod());
		assertEquals("FOO", new OAuth2AuthenticationDetails(mock("FOO")).getMethod());
	}

	@Test
	public void testGetRequestURI() {
		assertNull(new OAuth2AuthenticationDetails(mock()).getRequestURI());
		assertEquals("/bar", new OAuth2AuthenticationDetails(mock(null, "/bar")).getRequestURI());
	}

	/**
	 * Returns a new mock HttpServletRequest for given parameters in given order.  All must be {@code String}s
	 * (if provided), except the third, which must be a {@code MockHttpSession}.
	 *
	 * @param args method, requestURI, session, remoteAddr, token type, token value
	 */
	private MockHttpServletRequest mock(Object... args) {
		MockHttpServletRequest request = new MockHttpServletRequest(args.length < 1 ? null : (String)args[0],
						args.length < 2 ? null : (String)args[1]);
		request.setSession(args.length < 3 ? null : (MockHttpSession)args[2]);
		request.setRemoteAddr(args.length < 4 ? null : (String)args[3]);
		request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, args.length < 5 ? null : (String)args[4]);
		request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, args.length < 6 ? null : (String)args[5]);
		return request;
	}

}
