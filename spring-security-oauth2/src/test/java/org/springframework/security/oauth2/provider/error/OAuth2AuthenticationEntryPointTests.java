/*
 * Copyright 2006-2011 the original author or authors.
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
package org.springframework.security.oauth2.provider.error;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;

/**
 * @author Dave Syer
 * 
 */
public class OAuth2AuthenticationEntryPointTests {

	private OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	{
		entryPoint.setRealmName("foo");
	}

	@Test
	public void testCommenceWithJson() throws Exception {
		request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
		assertEquals("{\"error\":\"unauthorized\",\"error_description\":\"Bad\"}", response.getContentAsString());
		assertTrue(response.getContentType().contains(MediaType.APPLICATION_JSON_VALUE));
		assertEquals(null, response.getErrorMessage());
	}

	@Test
	public void testCommenceWithOAuth2Exception() throws Exception {
		request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
		entryPoint.commence(request, response, new BadCredentialsException("Bad", new InvalidClientException(
				"Bad client")));
		assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
		assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"Bad client\"}", response.getContentAsString());
		assertTrue(response.getContentType().contains(MediaType.APPLICATION_JSON_VALUE));
		assertEquals(null, response.getErrorMessage());
	}

	@Test
	public void testCommenceWithXml() throws Exception {
		request.addHeader("Accept", MediaType.APPLICATION_XML_VALUE);
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
		assertEquals("<oauth><error_description>Bad</error_description><error>unauthorized</error></oauth>",
				response.getContentAsString());
		assertEquals(MediaType.APPLICATION_XML_VALUE, response.getContentType());
		assertEquals(null, response.getErrorMessage());
	}

	@Test
	public void testTypeName() throws Exception {
		entryPoint.setTypeName("Foo");
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		assertEquals("Foo realm=\"foo\", error=\"unauthorized\", error_description=\"Bad\"",
				response.getHeader("WWW-Authenticate"));
	}

	@Test
	public void testCommenceWithEmptyAccept() throws Exception {
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
		assertEquals("{\"error\":\"unauthorized\",\"error_description\":\"Bad\"}", response.getContentAsString());
		assertTrue(MediaType.APPLICATION_JSON.isCompatibleWith(MediaType.valueOf(response.getContentType())));
		assertEquals(null, response.getErrorMessage());
	}

	@Test
	public void testCommenceWithHtmlAccept() throws Exception {
		request.addHeader("Accept", MediaType.TEXT_HTML_VALUE);
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		// TODO: maybe use forward / redirect for HTML content?
		assertEquals(HttpServletResponse.SC_NOT_ACCEPTABLE, response.getStatus());
		assertEquals("", response.getContentAsString());
		assertEquals(null, response.getErrorMessage());
	}

	@Test
	public void testCommenceWithHtmlAndJsonAccept() throws Exception {
		request.addHeader("Accept", String.format("%s,%s", MediaType.TEXT_HTML_VALUE, MediaType.APPLICATION_JSON));
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
		assertEquals(null, response.getErrorMessage());
	}

}
