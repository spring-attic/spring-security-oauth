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

package org.springframework.security.oauth2.provider.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Collections;

import javax.servlet.FilterChain;

import org.junit.After;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class TestOAuth2AuthenticationProcessingFilter {

	private OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala");

	private OAuth2Authentication authentication = new OAuth2Authentication(new AuthorizationRequest(
			Collections.<String, String> emptyMap()), userAuthentication);

	private FilterChain chain = Mockito.mock(FilterChain.class);

	{
		filter.setAuthenticationManager(new AuthenticationManager() {

			public Authentication authenticate(Authentication request) throws AuthenticationException {
				authentication.setDetails(request.getDetails());
				return authentication;
			}
		});
	}
	
	@After
	public void clear() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testDetailsAdded() throws Exception {
		request.addHeader("Authorization", "Bearer FOO");
		filter.doFilter(request, null, chain );
		assertNotNull(request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE));
		Authentication result = SecurityContextHolder.getContext().getAuthentication();
		assertEquals(authentication, result);
		assertNotNull(result.getDetails());
	}

}
