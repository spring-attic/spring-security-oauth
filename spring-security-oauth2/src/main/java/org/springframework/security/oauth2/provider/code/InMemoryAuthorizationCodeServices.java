package org.springframework.security.oauth2.provider.code;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of authorization code services that stores the codes and authentication in memory.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class InMemoryAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

	protected final ConcurrentHashMap<String, AuthorizationRequestHolder> authorizationCodeStore = new ConcurrentHashMap<String, AuthorizationRequestHolder>();

	@Override
	protected void store(String code, AuthorizationRequestHolder authentication) {
		this.authorizationCodeStore.put(code, authentication);
	}

	@Override
	public AuthorizationRequestHolder remove(String code) {
		AuthorizationRequestHolder auth = this.authorizationCodeStore.remove(code);
		return auth;
	}

}
