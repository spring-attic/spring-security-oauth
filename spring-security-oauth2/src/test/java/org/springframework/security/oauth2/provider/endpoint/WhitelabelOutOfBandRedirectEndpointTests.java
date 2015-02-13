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


package org.springframework.security.oauth2.provider.endpoint;

import static org.junit.Assert.assertTrue;

import java.util.HashMap;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author Miyamoto Daisuke
 *
 */
public class WhitelabelOutOfBandRedirectEndpointTests {
	
	private WhitelabelOutOfBandRedirectEndpoint endpoint = new WhitelabelOutOfBandRedirectEndpoint();
	private MockHttpServletRequest request = new MockHttpServletRequest();
	private MockHttpServletResponse response = new MockHttpServletResponse();

	@Test
	public void testOutOfBandRedirectPage() throws Exception {
		request.setContextPath("/foo");
		HashMap<String, Object> model = new HashMap<String, Object>();
		String code = "thecode";
		String err = null;
		String desc = null;
		String state = "thestate";
		ModelAndView result = endpoint.getAuthorizationCodeDisplay(model, code, err, desc, state);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.contains("<title>Success code=thecode&state=thestate</title>"));
		assertTrue("Wrong content: " + content, content.contains("Authorization Code"));
		assertTrue("Wrong content: " + content, content.contains(": thecode"));
		assertTrue("Wrong content: " + content, !content.contains("${"));
		assertTrue("Wrong content: " + content, !content.contains("%"));
	}

	@Test
	public void testOutOfBandRedirectPageWithUnexpectedCode() throws Exception {
		request.setContextPath("/foo");
		HashMap<String, Object> model = new HashMap<String, Object>();
		String code = "<script>alert('hello, hello!');</script>";
		String err = null;
		String desc = null;
		String state = "thestate";
		ModelAndView result = endpoint.getAuthorizationCodeDisplay(model, code, err, desc, state);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.contains("Authorization Code"));
		assertTrue("Wrong content: " + content, content.contains("<title>Success code=invalid&state=thestate</title>"));
		assertTrue("Wrong content: " + content, content.contains(": invalid"));
		assertTrue("Wrong content: " + content, !content.contains("<script>alert('hello, hello!');</script>"));
		assertTrue("Wrong content: " + content, !content.contains("${"));
		assertTrue("Wrong content: " + content, !content.contains("%"));
	}

	@Test
	public void testOutOfBandRedirectPageWithUnexpectedState() throws Exception {
		request.setContextPath("/foo");
		String code = "thecode";
		String err = null;
		String desc = null;
		String state = "<script>alert('hello, hello!');</script>";
		HashMap<String, Object> model = new HashMap<String, Object>();
		ModelAndView result = endpoint.getAuthorizationCodeDisplay(model, code, err, desc, state);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.contains("Authorization Code"));
		assertTrue("Wrong content: " + content, content.contains("<title>Success code=thecode&state=invalid</title>"));
		assertTrue("Wrong content: " + content, content.contains(": thecode"));
		assertTrue("Wrong content: " + content, !content.contains("<script>alert('hello, hello!');</script>"));
		assertTrue("Wrong content: " + content, !content.contains("${"));
		assertTrue("Wrong content: " + content, !content.contains("%"));
	}

	@Test
	public void testOutOfBandRedirectPageWithDeniedError() throws Exception {
		request.setContextPath("/foo");
		String code = null;
		String err = "access_denied";
		String desc = "User denied access";
		String state = "thestate";
		HashMap<String, Object> model = new HashMap<String, Object>();
		ModelAndView result = endpoint.getAuthorizationCodeDisplay(model, code, err, desc, state);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.contains("Authorization Code"));
		assertTrue("Wrong content: " + content, content.contains("<title>Denied error=access_denied&error_description=User%20denied%20access&state=thestate</title>"));
		assertTrue("Wrong content: " + content, content.contains(": access_denied"));
		assertTrue("Wrong content: " + content, content.contains(": User denied access"));
		assertTrue("Wrong content: " + content, !content.contains("${"));
//		assertTrue("Wrong content: " + content, !content.contains("%")); // contains "%20"
	}
}
