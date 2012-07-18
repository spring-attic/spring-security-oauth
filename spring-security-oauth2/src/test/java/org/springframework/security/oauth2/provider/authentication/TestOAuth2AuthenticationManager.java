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

import java.util.Collections;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * @author Dave Syer
 * 
 */
public class TestOAuth2AuthenticationManager {

	private OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();
	
	private ResourceServerTokenServices tokenServices = Mockito.mock(ResourceServerTokenServices.class);

	private Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala");

	private OAuth2Authentication authentication = new OAuth2Authentication(new DefaultAuthorizationRequest(
			Collections.<String, String> emptyMap()), userAuthentication);
	
	{
		manager.setTokenServices(tokenServices);
	}

	@Test
	public void testDetailsAdded() throws Exception {
		Mockito.when(tokenServices.loadAuthentication("FOO")).thenReturn(authentication);
		PreAuthenticatedAuthenticationToken request = new PreAuthenticatedAuthenticationToken("FOO", "");
		request.setDetails("BAR");
		Authentication result = manager.authenticate(request);
		assertEquals(authentication, result);
		assertEquals("BAR", result.getDetails());
	}

}
