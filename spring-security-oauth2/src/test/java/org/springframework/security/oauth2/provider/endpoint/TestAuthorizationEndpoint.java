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
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.TokenGranter;
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
		parameters.put("redirect_uri", redirectUri);
		parameters.put("state", state);
		parameters.put("scope", scope);
		return endpoint.getClientToken(parameters);
	}
	
	public TestAuthorizationEndpoint() {
		client = new BaseClientDetails();
		client.setRegisteredRedirectUri("http://anywhere.com");
	}

	@Test(expected = IllegalStateException.class)
	public void testMandatoryProperties() throws Exception {
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
	public void testAuthorizationCode() {
		endpoint.setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				return client;
			}
		});
		ModelAndView result = endpoint.authorize(model, "code", getAuthorizationRequest("foo", null, null, null).getParameters(),
				sessionStatus, principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
	}

	@Test
	public void testAuthorizationCodeWithMultipleResponseTypes() {
		endpoint.setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				return client;
			}
		});
		ModelAndView result = endpoint.authorize(model, "code other",
				getAuthorizationRequest("foo", null, null, null).getParameters(), sessionStatus, principal);
		assertEquals("forward:/oauth/confirm_access", result.getViewName());
	}

	@Test
	public void testImplicit() {
		endpoint.setTokenGranter(new TokenGranter() {
			public OAuth2AccessToken grant(String grantType, Map<String, String> parameters, String clientId,
					Set<String> scope) {
				return null;
			}
		});
		endpoint.setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				return new BaseClientDetails();
			}
		});
		ModelAndView result = endpoint.authorize(model, "token",
				getAuthorizationRequest("foo", "http://anywhere.com", null, null).getParameters(), sessionStatus, principal);
		assertTrue("Wrong view: " + result, ((RedirectView) result.getView()).getUrl()
				.startsWith("http://anywhere.com"));
	}

	@Test
	public void testApproveOrDeny() {
		endpoint.setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				return new BaseClientDetails();
			}
		});
		View result = endpoint.approveOrDeny(true, getAuthorizationRequest("foo", "http://anywhere.com", null, null),
				sessionStatus, principal);
		assertTrue("Wrong view: " + result, ((RedirectView) result).getUrl().startsWith("http://anywhere.com"));
	}

	// Commented out this test as it causes bug SECOAUTH-191
	//@Test
	public void testDirectApproval() {
		endpoint.setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				return new BaseClientDetails();
			}
		});
		ModelAndView result = endpoint.authorize(model, "code",
				getAuthorizationRequest("foo", "http://anywhere.com", null, null).getParameters(), sessionStatus, principal);
		String location = ((RedirectView) result.getView()).getUrl();
		assertTrue("Wrong view: " + result, location.startsWith("http://anywhere.com"));
		assertTrue("Wrong view: " + result, location.contains("code="));
	}

}
