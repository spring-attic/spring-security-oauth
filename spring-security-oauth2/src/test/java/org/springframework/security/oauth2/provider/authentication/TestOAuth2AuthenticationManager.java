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


package org.springframework.security.oauth2.provider.authentication;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
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

	private OAuth2Authentication authentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(null, "foo", null, false, null, null, null, null), userAuthentication);
	
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
