package org.springframework.security.oauth2.provider.code;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of authorization code services that stores the codes and authentication in memory.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class InMemoryAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

	protected final ConcurrentHashMap<String, UnconfirmedAuthorizationCodeAuthenticationTokenHolder> authorizationCodeStore = new ConcurrentHashMap<String, UnconfirmedAuthorizationCodeAuthenticationTokenHolder>();

	@Override
	protected void store(String code, UnconfirmedAuthorizationCodeAuthenticationTokenHolder authentication) {
		this.authorizationCodeStore.put(code, authentication);
	}

	@Override
	public UnconfirmedAuthorizationCodeAuthenticationTokenHolder remove(String code) {
		UnconfirmedAuthorizationCodeAuthenticationTokenHolder auth = this.authorizationCodeStore.remove(code);
		return auth;
	}

}
