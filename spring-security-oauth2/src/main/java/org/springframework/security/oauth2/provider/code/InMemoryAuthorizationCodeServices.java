package org.springframework.security.oauth2.provider.code;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Implementation of authorization code services that stores the codes and authentication in memory.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class InMemoryAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

	protected final ConcurrentHashMap<String, OAuth2Authentication> authorizationCodeStore = new ConcurrentHashMap<String, OAuth2Authentication>();

	@Override
	protected void store(String code, OAuth2Authentication authentication) {
		this.authorizationCodeStore.put(code, authentication);
	}

	@Override
	public OAuth2Authentication remove(String code) {
		OAuth2Authentication auth = this.authorizationCodeStore.remove(code);
		return auth;
	}

}
