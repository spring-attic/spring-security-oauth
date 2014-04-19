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
package org.springframework.security.oauth2.provider.approval;

import static org.junit.Assert.assertTrue;

import java.util.HashMap;

import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * @author Dave Syer
 * 
 */
public class TokenStoreUserApprovalHandlerTests {

	private TokenStoreUserApprovalHandler handler = new TokenStoreUserApprovalHandler();

	private DefaultTokenServices tokenServices = new DefaultTokenServices();
	
	private DefaultOAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(null);

	{
		InMemoryTokenStore tokenStore = new InMemoryTokenStore();
		tokenServices.setTokenStore(tokenStore);
		handler.setTokenStore(tokenStore);
		handler.setRequestFactory(requestFactory);
	}

	@Test(expected = IllegalStateException.class)
	public void testMandatoryProperties() throws Exception {
		handler = new TokenStoreUserApprovalHandler();
		handler.afterPropertiesSet();
	}

	@Test
	public void testBasicApproval() {
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put(OAuth2Utils.USER_OAUTH_APPROVAL, "true");
		AuthorizationRequest request = new AuthorizationRequest(parameters, null, null, null, null, null, false, null, null, null);
		request.setApproved(true); // This is enough to be explicitly approved
		assertTrue(handler.isApproved(request , new TestAuthentication("marissa", true)));
	}

	@Test
	public void testMemorizedApproval() {
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put(OAuth2Utils.USER_OAUTH_APPROVAL, "false");
		parameters.put("client_id", "foo");
		AuthorizationRequest authorizationRequest = new AuthorizationRequest(parameters, null, "foo", null, null, null, false, null, null, null);
		authorizationRequest.setApproved(false);
		TestAuthentication userAuthentication = new TestAuthentication("marissa", true);
		OAuth2Request storedOAuth2Request = requestFactory.createOAuth2Request(authorizationRequest);
		
		tokenServices.createAccessToken(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
		authorizationRequest = handler.checkForPreApproval(authorizationRequest, userAuthentication);
		assertTrue(handler.isApproved(authorizationRequest, userAuthentication));
	}

	protected static class TestAuthentication extends AbstractAuthenticationToken {

		private static final long serialVersionUID = 1L;
		private String principal;

		public TestAuthentication(String name, boolean authenticated) {
			super(null);
			setAuthenticated(authenticated);
			this.principal = name;
		}

		public Object getCredentials() {
			return null;
		}

		public Object getPrincipal() {
			return this.principal;
		}
	}

}
