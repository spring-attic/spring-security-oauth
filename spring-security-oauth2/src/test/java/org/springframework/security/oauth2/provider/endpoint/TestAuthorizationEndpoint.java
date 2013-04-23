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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.security.oauth2.provider.AuthorizationRequest.REDIRECT_URI;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;

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
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
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

	private DefaultAuthorizationRequest getAuthorizationRequest(String clientId, String redirectUri, String state,
			String scope) {
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		if (redirectUri != null) {
			parameters.put("redirect_uri", redirectUri);
		}
		if (state != null) {
			parameters.put("state", state);
		}
		if (scope != null) {
			parameters.put("scope", scope);
		}
		return new DefaultAuthorizationRequest(parameters);
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
		endpoint.setRedirectResolver(new DefaultRedirectResolver());
		endpoint.afterPropertiesSet();
	}

	@Test(expected = IllegalStateException.class)
	public void testMandatoryProperties() throws Exception {
		endpoint = new AuthorizationEndpoint();
		endpoint.afterPropertiesSet();
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
		model.put("authorizationRequest", getAuthorizationRequest("foo", "http://anywhere.com#bar", null, null));
		View result = endpoint.approveOrDeny(
				Collections.singletonMap(AuthorizationRequest.USER_OAUTH_APPROVAL, "true"), model, sessionStatus,
				principal);
		assertEquals("http://anywhere.com?code=thecode#bar", ((RedirectView) result).getUrl());
	}

	@Test
	public void testAuthorizationCodeError() throws Exception {
		endpoint.setUserApprovalHandler(new UserApprovalHandler() {
			public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

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
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
				token.setAdditionalInformation(Collections.singletonMap("foo", (Object)"bar"));
				return token;
			}
		});
		endpoint.setUserApprovalHandler(new UserApprovalHandler() {
			public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
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
		assertTrue("Wrong token: " + result, url.contains("access_token="));
		assertTrue("Wrong token: " + result, url.contains("foo=bar"));
	}

	@Test
	public void testImplicitAppendsScope() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, AuthorizationRequest authorizationRequest) {
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
				token.setScope(Collections.singleton("read"));
				return token;
			}
		});
		endpoint.setUserApprovalHandler(new UserApprovalHandler() {
			public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"myscope");
		ModelAndView result = endpoint.authorize(model, "token", authorizationRequest.getAuthorizationParameters(),
				sessionStatus, principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong scope: " + result, url.contains("&scope=read"));
	}

	@Test
	public void testImplicitAppendsScopeWhenDefaulting() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, AuthorizationRequest authorizationRequest) {
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
				token.setScope(new LinkedHashSet<String>(Arrays.asList("read", "write")));
				return token;
			}
		});
		endpoint.setUserApprovalHandler(new UserApprovalHandler() {
			public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				null);
		ModelAndView result = endpoint.authorize(model, "token", authorizationRequest.getAuthorizationParameters(),
				sessionStatus, principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong scope: " + result, url.contains("&scope=read%20write"));
	}

	@Test(expected = InvalidScopeException.class)
	public void testImplicitPreApprovedButInvalid() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, AuthorizationRequest authorizationRequest) {
				throw new IllegalStateException("Shouldn't be called");
			}
		});
		endpoint.setUserApprovalHandler(new UserApprovalHandler() {
			public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		client.setScope(Collections.singleton("smallscope"));
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"bigscope");
		ModelAndView result = endpoint.authorize(model, "token", authorizationRequest.getAuthorizationParameters(),
				sessionStatus, principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
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
			public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

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
		DefaultAuthorizationRequest request = getAuthorizationRequest("foo", "http://anywhere.com", null, null);
		request.setApproved(true);
		model.put("authorizationRequest", request);
		View result = endpoint.approveOrDeny(null, model, sessionStatus, principal);
		assertTrue("Wrong view: " + result, ((RedirectView) result).getUrl().startsWith("http://anywhere.com"));
	}

	@Test
	public void testApprovalDenied() throws Exception {
		model.put("authorizationRequest", getAuthorizationRequest("foo", "http://anywhere.com", null, null));
		View result = endpoint.approveOrDeny(null, model, sessionStatus, principal);
		String url = ((RedirectView) result).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
		assertTrue("Wrong view: " + result, url.contains("error=access_denied"));
	}

	@Test
	public void testDirectApproval() throws Exception {
		ModelAndView result = endpoint.authorize(model, "code",
				getAuthorizationRequest("foo", "http://anywhere.com", null, null).getAuthorizationParameters(),
				sessionStatus, principal);
		// Should go to approval page (SECOAUTH-191)
		assertFalse(result.getView() instanceof RedirectView);
	}

	@Test
	public void testRedirectUriOptionalForAuthorization() throws Exception {
		ModelAndView result = endpoint.authorize(model, "code", getAuthorizationRequest("foo", null, null, null)
				.getAuthorizationParameters(), sessionStatus, principal);
		// RedirectUri parameter should be null (SECOAUTH-333), however the resolvedRedirectUri not
		DefaultAuthorizationRequest authorizationRequest = (DefaultAuthorizationRequest) result.getModelMap().get(
				"authorizationRequest");
		assertNull(authorizationRequest.getAuthorizationParameters().get(REDIRECT_URI));
		assertEquals("http://anywhere.com", authorizationRequest.getRedirectUri());
	}

	@Test
	public void testApproveOrDenyWithAuthorizationRequestWithoutRedirectUri() throws Exception {
		DefaultAuthorizationRequest request = getAuthorizationRequest("foo", null, null, null);
		request.setApproved(true);
		model.put("authorizationRequest", request);
		View result = endpoint.approveOrDeny(null, model, sessionStatus, principal);
		assertTrue("Redirect view with code: " + result,
				((RedirectView) result).getUrl().startsWith("http://anywhere.com?code="));
	}

	@Test
	public void testAuthorizeWithNoRedirectUri() {
		client.setRegisteredRedirectUri(Collections.<String> emptySet());
		DefaultAuthorizationRequest request = getAuthorizationRequest("foo", null, null, null);
		endpoint.setRedirectResolver(new RedirectResolver() {
			public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {
				return null;
			}
		});
		try {
			model.put("authorizationRequest", request);
			endpoint.approveOrDeny(null, model, sessionStatus, principal);
			fail("Contract of RedirectResolver is to return not-null redirecturi");
		}
		catch (RedirectMismatchException e) {
		}

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
