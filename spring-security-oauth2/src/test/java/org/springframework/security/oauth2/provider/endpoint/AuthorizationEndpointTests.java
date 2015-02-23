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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.InMemoryApprovalStore;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.support.SimpleSessionStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author Dave Syer
 * 
 */
public class AuthorizationEndpointTests {

	private AuthorizationEndpoint endpoint = new AuthorizationEndpoint();

	private HashMap<String, Object> model = new HashMap<String, Object>();

	private SimpleSessionStatus sessionStatus = new SimpleSessionStatus();

	private UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken("foo", "bar",
			Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

	private BaseClientDetails client;

	private AuthorizationRequest getAuthorizationRequest(String clientId, String redirectUri, String state,
			String scope, Set<String> responseTypes) {
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put(OAuth2Utils.CLIENT_ID, clientId);
		if (redirectUri != null) {
			parameters.put(OAuth2Utils.REDIRECT_URI, redirectUri);
		}
		if (state != null) {
			parameters.put(OAuth2Utils.STATE, state);
		}
		if (scope != null) {
			parameters.put(OAuth2Utils.SCOPE, scope);
		}
		if (responseTypes != null) {
			parameters.put(OAuth2Utils.RESPONSE_TYPE, OAuth2Utils.formatParameterList(responseTypes));
		}
		return new AuthorizationRequest(parameters, Collections.<String, String> emptyMap(),
				parameters.get(OAuth2Utils.CLIENT_ID),
				OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)), null, null, false,
				parameters.get(OAuth2Utils.STATE), parameters.get(OAuth2Utils.REDIRECT_URI),
				OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.RESPONSE_TYPE)));
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
			public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
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
		ModelAndView result = endpoint.authorize(model,
				getAuthorizationRequest("foo", null, null, "read", Collections.singleton("code"))
						.getRequestParameters(), sessionStatus, principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
	}

	@Test
	public void testApprovalStoreAddsScopes() throws Exception {
		ApprovalStoreUserApprovalHandler userApprovalHandler = new ApprovalStoreUserApprovalHandler();
		userApprovalHandler.setApprovalStore(new InMemoryApprovalStore());
		endpoint.setUserApprovalHandler(userApprovalHandler);
		ModelAndView result = endpoint.authorize(model,
				getAuthorizationRequest("foo", null, null, "read", Collections.singleton("code"))
						.getRequestParameters(), sessionStatus, principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
		assertTrue(result.getModel().containsKey("scopes"));
	}

	@Test(expected = OAuth2Exception.class)
	public void testStartAuthorizationCodeFlowForClientCredentialsFails() throws Exception {
		client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
		ModelAndView result = endpoint.authorize(model,
				getAuthorizationRequest("foo", null, null, null, Collections.singleton("code")).getRequestParameters(),
				sessionStatus, principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
	}

	@Test
	public void testAuthorizationCodeWithFragment() throws Exception {
		endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
		model.put("authorizationRequest",
				getAuthorizationRequest("foo", "http://anywhere.com#bar", null, null, Collections.singleton("code")));
		View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model,
				sessionStatus, principal);
		assertEquals("http://anywhere.com?code=thecode#bar", ((RedirectView) result).getUrl());
	}

	@Test
	public void testAuthorizationCodeWithQueryParams() throws Exception {
		endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
		model.put(
				"authorizationRequest",
				getAuthorizationRequest("foo", "http://anywhere.com?foo=bar", null, null, Collections.singleton("code")));
		View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model,
				sessionStatus, principal);
		assertEquals("http://anywhere.com?foo=bar&code=thecode", ((RedirectView) result).getUrl());
	}

	@Test
	public void testAuthorizationCodeWithTrickyState() throws Exception {
		endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
		model.put("authorizationRequest",
				getAuthorizationRequest("foo", "http://anywhere.com", " =?s", null, Collections.singleton("code")));
		View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model,
				sessionStatus, principal);
		assertEquals("http://anywhere.com?code=thecode&state=%20%3D?s", ((RedirectView) result).getUrl());
	}

	@Test
	public void testAuthorizationCodeWithMultipleQueryParams() throws Exception {
		endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
		model.put(
				"authorizationRequest",
				getAuthorizationRequest("foo", "http://anywhere.com?foo=bar&bar=foo", null, null,
						Collections.singleton("code")));
		View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model,
				sessionStatus, principal);
		assertEquals("http://anywhere.com?foo=bar&bar=foo&code=thecode", ((RedirectView) result).getUrl());
	}

	@Test
	public void testAuthorizationCodeWithTrickyQueryParams() throws Exception {
		endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
		model.put(
				"authorizationRequest",
				getAuthorizationRequest("foo", "http://anywhere.com?foo=b =&bar=f $", null, null,
						Collections.singleton("code")));
		View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model,
				sessionStatus, principal);
		String url = ((RedirectView) result).getUrl();
		assertEquals("http://anywhere.com?foo=b%20=&bar=f%20$&code=thecode", url);
		MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(url).build().getQueryParams();
		assertEquals("[b%20=]", params.get("foo").toString());
		assertEquals("[f%20$]", params.get("bar").toString());
	}

	@Test
	public void testAuthorizationCodeWithTrickyEncodedQueryParams() throws Exception {
		endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
		model.put(
				"authorizationRequest",
				getAuthorizationRequest("foo", "http://anywhere.com/path?foo=b%20%3D&bar=f%20$", null, null,
						Collections.singleton("code")));
		View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model,
				sessionStatus, principal);
		assertEquals("http://anywhere.com/path?foo=b%20%3D&bar=f%20$&code=thecode", ((RedirectView) result).getUrl());
	}

	@Test
	public void testAuthorizationCodeWithMoreTrickyEncodedQueryParams() throws Exception {
		endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices());
		model.put(
				"authorizationRequest",
				getAuthorizationRequest("foo", "http://anywhere?t=a%3Db%26ep%3Dtest%2540test.me", null, null,
						Collections.singleton("code")));
		View result = endpoint.approveOrDeny(Collections.singletonMap(OAuth2Utils.USER_OAUTH_APPROVAL, "true"), model,
				sessionStatus, principal);
		assertEquals("http://anywhere?t=a%3Db%26ep%3Dtest%2540test.me&code=thecode", ((RedirectView) result).getUrl());
	}

	@Test
	public void testAuthorizationCodeError() throws Exception {
		endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {
			public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		endpoint.setAuthorizationCodeServices(new StubAuthorizationCodeServices() {
			@Override
			public String createAuthorizationCode(OAuth2Authentication authentication) {
				throw new InvalidScopeException("FOO");
			}
		});
		ModelAndView result = endpoint.authorize(
				model,
				getAuthorizationRequest("foo", "http://anywhere.com", "mystate", "myscope",
						Collections.singleton("code")).getRequestParameters(), sessionStatus, principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
		assertTrue("No error: " + result, url.contains("?error="));
		assertTrue("Wrong state: " + result, url.contains("&state=mystate"));

	}

	@Test
	public void testAuthorizationCodeWithMultipleResponseTypes() throws Exception {
		Set<String> responseTypes = new HashSet<String>();
		responseTypes.add("code");
		responseTypes.add("other");
		ModelAndView result = endpoint.authorize(model,
				getAuthorizationRequest("foo", null, null, "read", responseTypes).getRequestParameters(),
				sessionStatus, principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
	}

	@Test
	public void testImplicitPreApproved() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {

			public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
				token.setAdditionalInformation(Collections.singletonMap("foo", (Object) "bar"));
				return token;

			}
		});
		endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {
			public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"myscope", Collections.singleton("token"));
		ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus,
				principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
		assertTrue("Wrong state: " + result, url.contains("&state=mystate"));
		assertTrue("Wrong token: " + result, url.contains("access_token="));
		assertTrue("Wrong token: " + result, url.contains("foo=bar"));
	}

	@Test
	public void testImplicitAppendsScope() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
				token.setScope(Collections.singleton("read"));
				return token;
			}
		});
		endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {
			public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"myscope", Collections.singleton("token"));
		ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus,
				principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong scope: " + result, url.contains("&scope=read"));
	}

	@Test
	public void testImplicitWithQueryParam() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
				return token;
			}
		});
		endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {
			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com?foo=bar",
				"mystate", "myscope", Collections.singleton("token"));
		ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus,
				principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong url: " + result, url.contains("foo=bar"));
	}

	@Test
	public void testImplicitWithAdditionalInfo() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
				token.setAdditionalInformation(Collections.<String, Object> singletonMap("foo", "bar"));
				return token;
			}
		});
		endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {
			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"myscope", Collections.singleton("token"));
		ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus,
				principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong url: " + result, url.contains("foo=bar"));
	}

	@Test
	public void testImplicitAppendsScopeWhenDefaulting() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
				token.setScope(new LinkedHashSet<String>(Arrays.asList("read", "write")));
				return token;
			}
		});
		endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {
			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}

			public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}
		});
		client.setScope(Collections.singleton("read"));
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				null, Collections.singleton("token"));
		ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus,
				principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong scope: " + result, url.contains("&scope=read%20write"));
	}

	@Test(expected = InvalidScopeException.class)
	public void testImplicitPreApprovedButInvalid() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
				throw new IllegalStateException("Shouldn't be called");
			}
		});
		endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {
			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}

			public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}
		});
		client.setScope(Collections.singleton("smallscope"));
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"bigscope", Collections.singleton("token"));
		ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus,
				principal);
		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
	}

	@Test
	public void testImplicitUnapproved() throws Exception {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
				return null;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"myscope", Collections.singleton("token"));
		ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus,
				principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
	}

	@Test
	public void testImplicitError() throws Exception {
		endpoint.setUserApprovalHandler(new DefaultUserApprovalHandler() {
			public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
					Authentication userAuthentication) {
				return authorizationRequest;
			}

			public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
				return true;
			}
		});
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
				return null;
			}
		});
		AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "mystate",
				"myscope", Collections.singleton("token"));
		ModelAndView result = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus,
				principal);

		String url = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
		assertTrue("No error: " + result, url.contains("#error="));
		assertTrue("Wrong state: " + result, url.contains("&state=mystate"));

	}

	@Test
	public void testApproveOrDeny() throws Exception {
		AuthorizationRequest request = getAuthorizationRequest("foo", "http://anywhere.com", null, null,
				Collections.singleton("code"));
		request.setApproved(true);
		Map<String, String> approvalParameters = new HashMap<String, String>();
		approvalParameters.put("user_oauth_approval", "true");
		model.put("authorizationRequest", request);
		View result = endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
		assertTrue("Wrong view: " + result, ((RedirectView) result).getUrl().startsWith("http://anywhere.com"));
	}

	@Test
	public void testApprovalDenied() throws Exception {
		model.put("authorizationRequest",
				getAuthorizationRequest("foo", "http://anywhere.com", null, null, Collections.singleton("code")));
		Map<String, String> approvalParameters = new HashMap<String, String>();
		approvalParameters.put("user_oauth_approval", "false");
		View result = endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
		String url = ((RedirectView) result).getUrl();
		assertTrue("Wrong view: " + result, url.startsWith("http://anywhere.com"));
		assertTrue("Wrong view: " + result, url.contains("error=access_denied"));
	}

	@Test
	public void testDirectApproval() throws Exception {
		ModelAndView result = endpoint.authorize(model,
				getAuthorizationRequest("foo", "http://anywhere.com", null, "read", Collections.singleton("code"))
						.getRequestParameters(), sessionStatus, principal);
		// Should go to approval page (SECOAUTH-191)
		assertFalse(result.getView() instanceof RedirectView);
	}

	@Test
	public void testRedirectUriOptionalForAuthorization() throws Exception {
		ModelAndView result = endpoint.authorize(model,
				getAuthorizationRequest("foo", null, null, "read", Collections.singleton("code"))
						.getRequestParameters(), sessionStatus, principal);
		// RedirectUri parameter should be null (SECOAUTH-333), however the resolvedRedirectUri not
		AuthorizationRequest authorizationRequest = (AuthorizationRequest) result.getModelMap().get(
				"authorizationRequest");
		assertNull(authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI));
		assertEquals("http://anywhere.com", authorizationRequest.getRedirectUri());
	}

	/**
	 * Ensure that if the approval endpoint is called without a resolved redirect URI, the request fails.
	 * @throws Exception
	 */
	@Test(expected = InvalidRequestException.class)
	public void testApproveOrDenyWithOAuth2RequestWithoutRedirectUri() throws Exception {
		AuthorizationRequest request = getAuthorizationRequest("foo", null, null, null, Collections.singleton("code"));
		request.setApproved(true);
		Map<String, String> approvalParameters = new HashMap<String, String>();
		approvalParameters.put("user_oauth_approval", "true");
		model.put("authorizationRequest", request);
		endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);

	}

	private class StubAuthorizationCodeServices implements AuthorizationCodeServices {
		private OAuth2Authentication authentication;

		public String createAuthorizationCode(OAuth2Authentication authentication) {
			this.authentication = authentication;
			return "thecode";
		}

		public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {
			return authentication;
		}
	}

}
