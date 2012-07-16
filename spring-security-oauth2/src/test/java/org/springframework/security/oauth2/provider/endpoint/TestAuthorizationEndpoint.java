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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;
import org.springframework.web.bind.support.SimpleSessionStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

/**
 * @author Dave Syer
 * 
 */
public class TestAuthorizationEndpoint {

	private AuthorizationEndpoint endpoint = new AuthorizationEndpoint();

	private HashMap<String, Object> model = new HashMap<String, Object>();

	private SimpleSessionStatus sessionStatus = new SimpleSessionStatus();

	private UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken("foo", "bar",
			Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

	private BaseClientDetails client;

	private AuthorizationRequest getAuthorizationRequest(String clientId, String redirectUri, String state, String scope) {
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		if (redirectUri == null) {
			redirectUri = "http://anywhere.com";
		}
		parameters.put("redirect_uri", redirectUri);
		parameters.put("state", state);
		parameters.put("scope", scope);
		return new AuthorizationRequest(parameters);
	}

	@Before
	public void init() throws Exception {
		client = new BaseClientDetails();
		client.setRegisteredRedirectUri(Collections.singleton("http://anywhere.com"));
		client.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "implicit"));
		endpoint.setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				return client;
			}
		});
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, AuthorizationRequest authorizationRequest) {
				return null;
			}
		});
		endpoint.afterPropertiesSet();
	}

	@Test(expected = IllegalStateException.class)
	public void testMandatoryProperties() throws Exception {
		endpoint = new AuthorizationEndpoint();
		endpoint.afterPropertiesSet();
	}

	@Test
	public void testGetClientToken() {
		AuthorizationRequest clientToken = getAuthorizationRequest("foo", "http://anywhere.com", "bar", "baz");
		assertEquals("bar", clientToken.getState());
		assertEquals("foo", clientToken.getClientId());
		assertEquals("http://anywhere.com", clientToken.getRedirectUri());
		assertEquals("[baz]", clientToken.getScope().toString());
	}

	@Test
	public void testStartAuthorizationCodeFlow() throws Exception {
		ModelAndView result = endpoint.authorize(model, "code", getAuthorizationRequest("foo", null, null, null)
				.getAuthorizationParameters(), sessionStatus, principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
	}

	@Test(expected = OAuth2Exception.class)
	public void testStartAuthorizationCodeFlowForClientCredentialsFails() throws Exception {
		client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
		ModelAndView result = endpoint.authorize(model, "code", getAuthorizationRequest("foo", null, null, null)
				.getAuthorizationParameters(), sessionStatus, principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
	}

	@Test
	public void testAuthorizationCodeWithFragment() throws Exception {
		endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
		View result = endpoint.approveOrDeny(
				Collections.singletonMap(AuthorizationRequest.USER_OAUTH_APPROVAL, "true"),
				getAuthorizationRequest("foo", "http://anywhere.com#bar", null, null), sessionStatus, principal);
		assertEquals("http://anywhere.com?code=thecode#bar", ((RedirectView) result).getUrl());
	}

	@Test
	public void testAuthorizationCodeError() throws Exception {
		endpoint.setUserApprovalHandler(new UserApprovalHandler() {
			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices() {
			@Override
			public String createAuthorizationCode(AuthorizationRequestHolder authentication) {
				throw new InvalidScopeException("FOO");
			}
		});
		ModelAndView result = endpoint.authorize(model, "code",
				getAuthorizationRequest("foo", "http://anywhere.com", "mystate", "myscope")
						.getAuthorizationParameters(), sessionStatus, principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
		assertTrue("No error: " + result, url.contains("?error="));
		assertTrue("Wrong state: " + result, url.contains("&state=mystate"));

	}

	@Test
	public void testAuthorizationCodeWithMultipleResponseTypes() throws Exception {
		ModelAndView result = endpoint.authorize(model, "code other", getAuthorizationRequest("foo", null, null, null)
				.getAuthorizationParameters(), sessionStatus, principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
	}

	@Test
	public void testImplicitPreApproved() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, AuthorizationRequest authorizationRequest) {
				return new DefaultOAuth2AccessToken("FOO");
			}
		});
		endpoint.setUserApprovalHandler(new UserApprovalHandler() {
			public boolean isApproved(AuthorizationRequest authenticationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"myscope");
		ModelAndView result = endpoint.authorize(model, "token", authorizationRequest.getAuthorizationParameters(),
				sessionStatus, principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
		assertTrue("Wrong state: " + result, url.contains("&state=mystate"));
	}

	@Test
	public void testImplicitUnapproved() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, AuthorizationRequest authorizationRequest) {
				return null;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"myscope");
		ModelAndView result = endpoint.authorize(model, "token", authorizationRequest.getAuthorizationParameters(),
				sessionStatus, principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
	}

	@Test
	public void testImplicitError() throws Exception {
		endpoint.setUserApprovalHandler(new UserApprovalHandler() {
			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, AuthorizationRequest authorizationRequest) {
				return null;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"myscope");
		ModelAndView result = endpoint.authorize(model, "token", authorizationRequest.getAuthorizationParameters(),
				sessionStatus, principal);

		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
		assertTrue("No error: " + result, url.contains("#error="));
		assertTrue("Wrong state: " + result, url.contains("&state=mystate"));

	}

	@Test
	public void testApproveOrDeny() throws Exception {
		View result = endpoint.approveOrDeny(null, getAuthorizationRequest("foo", "http://anywhere.com", null, null).approved(true),
				sessionStatus, principal);
		assertTrue("Wrong view: " + result, ((RedirectView) result).getUrl().startsWith("http://anywhere.com"));
	}

	@Test
	public void testApprovalDenied() throws Exception {
		View result = endpoint.approveOrDeny(null, getAuthorizationRequest("foo", "http://anywhere.com", null, null).approved(false),
				sessionStatus, principal);
		String url = ((RedirectView) result).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
		assertTrue("Wrong view: "+ result, url.contains("error=access_denied"));
	}

	@Test
	public void testDirectApproval() throws Exception {
		ModelAndView result = endpoint.authorize(model, "code",
				getAuthorizationRequest("foo", "http://anywhere.com", null, null).getAuthorizationParameters(),
				sessionStatus, principal);
		// Should go to approval page (SECOAUTH-191)
		assertFalse(result.getView() instanceof RedirectView);
	}

	private class StubAuthorizationCodeServices implements AuthorizationCodeServices {
		private AuthorizationRequestHolder authentication;

		public String createAuthorizationCode(AuthorizationRequestHolder authentication) {
			this.authentication = authentication;
			return "thecode";
		}

		public AuthorizationRequestHolder consumeAuthorizationCode(String code) throws InvalidGrantException {
			return authentication;
		}
	}

}
