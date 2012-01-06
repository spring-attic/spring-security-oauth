package org.springframework.security.oauth2.provider.code;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;

/**
 * Services for issuing and storing authorization codes.
 * 
 * @author Ryan Heaton
 */
public interface AuthorizationCodeServices {

	/**
	 * Create a authorization code for the specified authentications.
	 * 
	 * @param authentication The authentications to store.
	 * @return The generated code.
	 */
	String createAuthorizationCode(AuthorizationRequestHolder authentication);

	/**
	 * Consume a authorization code.
	 * 
	 * @param code The authorization code to consume.
	 * @return The authentications associated with the code.
	 * @throws InvalidGrantException If the authorization code is invalid or expired.
	 */
	AuthorizationRequestHolder consumeAuthorizationCode(String code)
			throws InvalidGrantException;

}
