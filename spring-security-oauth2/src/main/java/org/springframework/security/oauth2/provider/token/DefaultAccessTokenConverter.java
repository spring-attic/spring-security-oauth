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
package org.springframework.security.oauth2.provider.token;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 * Default implementation of {@link AccessTokenConverter}.
 * 
 * @author Dave Syer
 * 
 */
public class DefaultAccessTokenConverter implements AccessTokenConverter {

	private UserAuthenticationConverter userTokenConverter = new DefaultUserAuthenticationConverter();
	
	/**
	 * Converter for the part of the data in the token representing a user.
	 * 
	 * @param userTokenConverter the userTokenConverter to set
	 */
	public void setUserTokenConverter(UserAuthenticationConverter userTokenConverter) {
		this.userTokenConverter = userTokenConverter;
	}

	public Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		Map<String, Object> response = new HashMap<String, Object>();
		OAuth2Request clientToken = authentication.getOAuth2Request();

		if (!authentication.isClientOnly()) {
			response.putAll(userTokenConverter.convertUserAuthentication(authentication.getUserAuthentication()));
		} else {
			if (clientToken.getAuthorities()!=null && !clientToken.getAuthorities().isEmpty()) {
				response.put(UserAuthenticationConverter.AUTHORITIES, clientToken.getAuthorities());
			}
		}

		if (token.getScope()!=null) {
			response.put(SCOPE, token.getScope());
		}
		if (token.getAdditionalInformation().containsKey(JTI)) {
			response.put(JTI, token.getAdditionalInformation().get(JTI));
		}

		if (token.getExpiration() != null) {
			response.put(EXP, token.getExpiration().getTime() / 1000);
		}

		response.putAll(token.getAdditionalInformation());

		response.put(CLIENT_ID, clientToken.getClientId());
		if (clientToken.getResourceIds() != null && !clientToken.getResourceIds().isEmpty()) {
			response.put(AUD, clientToken.getResourceIds());
		}
		return response;
	}

	public OAuth2AccessToken extractAccessToken(String value, Map<String, ?> map) {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(value);
		Map<String, Object> info = new HashMap<String, Object>(map);
		info.remove(EXP);
		info.remove(AUD);
		info.remove(CLIENT_ID);
		info.remove(SCOPE);
		if (map.containsKey(EXP)) {
			token.setExpiration(new Date((Long) map.get(EXP) * 1000L));
		}
		if (map.containsKey(JTI)) {
			info.put(JTI, map.get(JTI));
		}
		@SuppressWarnings("unchecked")
		Collection<String> scope = (Collection<String>) map.get(SCOPE);
		if (scope != null) {
			token.setScope(new HashSet<String>(scope));
		}
		token.setAdditionalInformation(info);
		return token;
	}

	public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
		Map<String, String> parameters = new HashMap<String, String>();
		@SuppressWarnings("unchecked")
		Set<String> scope = new LinkedHashSet<String>(map.containsKey(SCOPE) ? (Collection<String>) map.get(SCOPE)
				: Collections.<String>emptySet());
		Authentication user = userTokenConverter.extractAuthentication(map);
		String clientId = (String) map.get(CLIENT_ID);
		parameters.put(CLIENT_ID, clientId);
		@SuppressWarnings("unchecked")
		Set<String> resourceIds = new LinkedHashSet<String>(map.containsKey(AUD) ? (Collection<String>) map.get(AUD)
				: Collections.<String>emptySet());
		OAuth2Request request = new OAuth2Request(parameters, clientId, null, true, scope, resourceIds, null, null,
				null);
		return new OAuth2Authentication(request, user);
	}

}
