package org.springframework.security.oauth2.provider.authorization_code;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Services for issuing and storing authorization codes.
 *
 * @author Ryan Heaton
 */
public interface AuthorizationCodeServices {

  /**
   * Create a authorization code for the specified authentication.
   *
   * @param authentication The authentication to store.
   * @return The generated code.
   */
  String createAuthorizationCode(OAuth2Authentication<? extends UnconfirmedAuthorizationCodeAuthenticationToken, ? extends Authentication> authentication);

  /**
   * Consume a authorization code.
   *
   * @param code The authorization code to consume.
   * @return The authentication associated with the code.
   * @throws InvalidGrantException If the authorization code is invalid or expired.
   */
  OAuth2Authentication<? extends UnconfirmedAuthorizationCodeAuthenticationToken, ? extends Authentication> consumeAuthorizationCode(String code) throws InvalidGrantException ;

}
