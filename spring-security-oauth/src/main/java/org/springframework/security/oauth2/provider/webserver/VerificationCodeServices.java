package org.springframework.security.oauth2.provider.webserver;

import org.springframework.security.oauth2.common.exceptions.InvalidVerificationCodeException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Services for issuing and storing verification codes.
 *
 * @author Ryan Heaton
 */
public interface VerificationCodeServices {

  /**
   * Create a verification code for the specified authentication.
   *
   * @param authentication The authentication to store.
   * @return The generated code.
   */
  String createVerificationCode(OAuth2Authentication authentication);

  /**
   * Consume a verification code.
   *
   * @param code The verification code to consume.
   * @return The authentication associated with the code.
   * @throws InvalidVerificationCodeException If the verification code is invalid or expired.
   */
  OAuth2Authentication consumeVerificationCode(String code) throws InvalidVerificationCodeException;

}
