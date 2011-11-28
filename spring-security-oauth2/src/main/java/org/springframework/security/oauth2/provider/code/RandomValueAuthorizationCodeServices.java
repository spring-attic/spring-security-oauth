package org.springframework.security.oauth2.provider.code;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

/**
 * Base implementation for authorization code services that generates a random-value authorization code.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public abstract class RandomValueAuthorizationCodeServices implements AuthorizationCodeServices {

	private RandomValueStringGenerator generator = new RandomValueStringGenerator();

	protected abstract void store(String code, UnconfirmedAuthorizationCodeAuthenticationTokenHolder authentication);

	protected abstract UnconfirmedAuthorizationCodeAuthenticationTokenHolder remove(String code);

	public String createAuthorizationCode(UnconfirmedAuthorizationCodeAuthenticationTokenHolder authentication) {
		String code = generator.generate();
		store(code, authentication);
		return code;
	}

	public UnconfirmedAuthorizationCodeAuthenticationTokenHolder consumeAuthorizationCode(String code)
			throws InvalidGrantException {
		UnconfirmedAuthorizationCodeAuthenticationTokenHolder auth = this.remove(code);
		if (auth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + code);
		}
		return auth;
	}

}
