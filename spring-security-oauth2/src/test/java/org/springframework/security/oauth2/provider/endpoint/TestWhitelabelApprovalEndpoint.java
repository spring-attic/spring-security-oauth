/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.springframework.security.oauth2.provider.endpoint;

import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author Dave Syer
 *
 */
public class TestWhitelabelApprovalEndpoint {
	
	private WhitelabelApprovalEndpoint endpoint = new WhitelabelApprovalEndpoint();
	private Map<String, String> parameters = new HashMap<String, String>();
	private MockHttpServletRequest request = new MockHttpServletRequest();
	private MockHttpServletResponse response = new MockHttpServletResponse();

	@Test
	public void testApprovalPage() throws Exception {
		request.setContextPath("/foo");
		parameters.put("client_id", "client");
		ModelAndView result = endpoint.getAccessConfirmation(new AuthorizationRequest(parameters));
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.contains("<form"));
		assertTrue("Wrong content: " + content, content.contains("/foo/oauth/authorize"));
		assertTrue("Wrong content: " + content, !content.contains("${"));
	}
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

}
