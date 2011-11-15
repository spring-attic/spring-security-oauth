package org.springframework.security.oauth2.client.token.service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Token services that simply stores any tokens in memory.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class InMemoryOAuth2ClientTokenServices implements OAuth2ClientTokenServices {

	private static final Map<String, Map<String, OAuth2AccessToken>> USER_TO_RESOURCE_TO_TOKEN = new ConcurrentHashMap<String, Map<String, OAuth2AccessToken>>();

	private static final Map<OAuth2ProtectedResourceDetails, OAuth2AccessToken> RESOURCE_TO_TOKEN = new ConcurrentHashMap<OAuth2ProtectedResourceDetails, OAuth2AccessToken>();

	public OAuth2AccessToken getToken(Authentication authentication, OAuth2ProtectedResourceDetails resource) {
		if (authentication != null && authentication.isAuthenticated()) {
			Map<String, OAuth2AccessToken> resourceMap = USER_TO_RESOURCE_TO_TOKEN.get(authentication.getName());
			return resourceMap == null ? null : resourceMap.get(resource.getId());
		}

		return RESOURCE_TO_TOKEN.get(resource);
	}

	public void storeToken(Authentication authentication, OAuth2ProtectedResourceDetails resource,
			OAuth2AccessToken token) {
		if (authentication != null && authentication.isAuthenticated()) {
			Map<String, OAuth2AccessToken> resourceMap = USER_TO_RESOURCE_TO_TOKEN.get(authentication.getName());
			if (resourceMap == null) {
				resourceMap = new ConcurrentHashMap<String, OAuth2AccessToken>();
				USER_TO_RESOURCE_TO_TOKEN.put(authentication.getName(), resourceMap);
			}
			resourceMap.put(resource.getId(), token);
		} else {
			RESOURCE_TO_TOKEN.put(resource, token);
		}
	}

	public void updateToken(Authentication authentication, OAuth2ProtectedResourceDetails resource,
			OAuth2AccessToken oldToken, OAuth2AccessToken replacement) {
		storeToken(authentication, resource, replacement);
	}

	public void removeToken(Authentication authentication, OAuth2ProtectedResourceDetails resource) {
		if (authentication != null && authentication.isAuthenticated()) {
			Map<String, OAuth2AccessToken> resourceMap = USER_TO_RESOURCE_TO_TOKEN.get(authentication.getName());
			if (resourceMap != null) {
				resourceMap.remove(resource.getId());
			}
		} else {
			RESOURCE_TO_TOKEN.remove(resource);
		}
	}
}
