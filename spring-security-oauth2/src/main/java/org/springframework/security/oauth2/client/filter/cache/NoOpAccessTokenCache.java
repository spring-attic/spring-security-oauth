package org.springframework.security.oauth2.client.filter.cache;

import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Basic, no-op implementation of the access token cache. Forces clients to obtain a token for every request.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class NoOpAccessTokenCache implements AccessTokenCache {

	public Map<String, OAuth2AccessToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response) {
		return Collections.emptyMap();
	}

	public void rememberTokens(Map<OAuth2ProtectedResourceDetails, OAuth2AccessToken> map, HttpServletRequest request,
			HttpServletResponse response) {
	}

}
