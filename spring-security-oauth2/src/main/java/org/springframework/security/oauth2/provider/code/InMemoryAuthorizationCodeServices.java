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

	protected final ConcurrentHashMap<String, OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken>> authorizationCodeStore = new ConcurrentHashMap<String, OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken>>();

	@Override
	protected void store(String code,
			OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken> authentication) {
		this.authorizationCodeStore.put(code, authentication);
	}

	@Override
	public OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken> remove(String code) {
		OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken> auth = this.authorizationCodeStore
				.remove(code);
		return auth;
	}

}
