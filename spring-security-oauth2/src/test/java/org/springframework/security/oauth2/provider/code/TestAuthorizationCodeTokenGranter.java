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

package org.springframework.security.oauth2.provider.code;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.AuthorizationRequestFactory;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;

/**
 * @author Dave Syer
 * 
 */
public class TestAuthorizationCodeTokenGranter {

	private DefaultTokenServices providerTokenServices = new DefaultTokenServices();

	BaseClientDetails client = new BaseClientDetails("foo", "resource", "scope", "authorization_code", "ROLE_CLIENT");

	private AuthorizationRequestFactory authorizationRequestFactory = new DefaultAuthorizationRequestFactory(
			new ClientDetailsService() {
				public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
					return client;
				}
			});

	private AuthorizationCodeServices authorizationCodeServices = new InMemoryAuthorizationCodeServices();

	private Map<String, String> parameters = new HashMap<String, String>();

	public TestAuthorizationCodeTokenGranter() {
		providerTokenServices.setTokenStore(new InMemoryTokenStore());
	}

	@Test
	public void testAuthorizationCodeGrant() {
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("foo", Arrays.asList("scope"),
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_CLIENT"), Collections.<String> emptySet());
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new AuthorizationRequestHolder(
				authorizationRequest, userAuthentication));
		parameters.put("code", code);
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, authorizationRequestFactory);
		OAuth2AccessToken token = granter.grant("authorization_code", parameters, "foo", null);
		assertTrue(providerTokenServices.loadAuthentication(token.getValue()).isAuthenticated());
	}

	@Test
	public void testAuthorizationCodeGrantWithNoClientAuthorities() {
		client.setAuthorities(Collections.<GrantedAuthority> emptySet());
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("foo", Arrays.asList("scope"),
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_CLIENT"), Collections.<String> emptySet());
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		String code = authorizationCodeServices.createAuthorizationCode(new AuthorizationRequestHolder(
				authorizationRequest, userAuthentication));
		parameters.put("code", code);
		AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(providerTokenServices,
				authorizationCodeServices, authorizationRequestFactory);
		OAuth2AccessToken token = granter.grant("authorization_code", parameters, "foo", null);
		assertTrue(providerTokenServices.loadAuthentication(token.getValue()).isAuthenticated());
	}

}
