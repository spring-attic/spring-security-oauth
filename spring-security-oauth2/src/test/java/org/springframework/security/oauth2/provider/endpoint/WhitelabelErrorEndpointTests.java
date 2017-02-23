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

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author Dave Syer
 *
 */
public class WhitelabelErrorEndpointTests {
	
	private WhitelabelErrorEndpoint endpoint = new WhitelabelErrorEndpoint();
	private MockHttpServletRequest request = new MockHttpServletRequest();
	private MockHttpServletResponse response = new MockHttpServletResponse();

	@Test
	public void testErrorPage() throws Exception {
		request.setContextPath("/foo");
		request.setAttribute("error", new InvalidClientException("FOO"));
		ModelAndView result = endpoint.handleError(request);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.contains("OAuth Error"));
		assertTrue("Wrong content: " + content, content.contains("invalid_client"));
	}

	@Test
	public void testErrorPageNoError() throws Exception {
		request.setContextPath("/foo");
		ModelAndView result = endpoint.handleError(request);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.contains("OAuth Error"));
		assertTrue("Wrong content: " + content, content.contains("Unknown"));
	}

	@Test
	public void testErrorPageXSS() throws Exception {
		request.setAttribute("error", new InvalidGrantException("Invalid grant : <script>alert('XSS');</script>"));
		ModelAndView result = endpoint.handleError(request);
		result.getView().render(result.getModel(), request, response);
		String content = response.getContentAsString();
		assertFalse("Wrong content : " + content, content.contains("<script>"));
	}
}
