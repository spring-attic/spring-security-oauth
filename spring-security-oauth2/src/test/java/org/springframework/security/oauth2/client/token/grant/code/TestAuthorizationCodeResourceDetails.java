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

package org.springframework.security.oauth2.client.token.grant.code;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;

/**
 * @author Dave Syer
 *
 */
public class TestAuthorizationCodeResourceDetails {
	
	private AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();

	@Test
	public void testGetDefaultRedirectUri() {
		details.setPreEstablishedRedirectUri("http://anywhere.com");
		DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setCurrentUri("http://nowhere.com");
		assertEquals("http://nowhere.com", details.getRedirectUri(request));
	}

	@Test
	public void testGetOverrideRedirectUri() {
		details.setPreEstablishedRedirectUri("http://anywhere.com");
		details.setUseCurrentUri(false);
		DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setCurrentUri("http://nowhere.com");
		assertEquals("http://anywhere.com", details.getRedirectUri(request));
	}

}
