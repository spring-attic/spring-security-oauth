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

	protected abstract void store(String code, AuthorizationRequestHolder authentication);

	protected abstract AuthorizationRequestHolder remove(String code);

	public String createAuthorizationCode(AuthorizationRequestHolder authentication) {
		String code = generator.generate();
		store(code, authentication);
		return code;
	}

	public AuthorizationRequestHolder consumeAuthorizationCode(String code)
			throws InvalidGrantException {
		AuthorizationRequestHolder auth = this.remove(code);
		if (auth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + code);
		}
		return auth;
	}

}
