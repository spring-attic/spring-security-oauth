package org.springframework.security.oauth2.provider.code;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Services for issuing and storing authorization codes.
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 */
@Deprecated
public interface AuthorizationCodeServices {

	/**
	 * Create a authorization code for the specified authentications.
	 * 
	 * @param authentication The authentications to store.
	 * @return The generated code.
	 */
	String createAuthorizationCode(OAuth2Authentication authentication);

	/**
	 * Consume a authorization code.
	 * 
	 * @param code The authorization code to consume.
	 * @return The authentications associated with the code.
	 * @throws InvalidGrantException If the authorization code is invalid or expired.
	 */
	OAuth2Authentication consumeAuthorizationCode(String code)
			throws InvalidGrantException;

}
