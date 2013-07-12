package org.springframework.security.oauth2.provider.code;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Base implementation for authorization code services that generates a random-value authorization code.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public abstract class RandomValueAuthorizationCodeServices implements AuthorizationCodeServices {

	private RandomValueStringGenerator generator = new RandomValueStringGenerator();

	protected abstract void store(String code, OAuth2Authentication authentication);

	protected abstract OAuth2Authentication remove(String code);

	public String createAuthorizationCode(OAuth2Authentication authentication) {
		String code = generator.generate();
		store(code, authentication);
		return code;
	}

	public OAuth2Authentication consumeAuthorizationCode(String code)
			throws InvalidGrantException {
		OAuth2Authentication auth = this.remove(code);
		if (auth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + code);
		}
		return auth;
	}

}
