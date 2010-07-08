package org.springframework.security.oauth2.provider.webserver;

import org.springframework.security.oauth2.common.exceptions.InvalidVerificationCodeException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of verification code services that stores the codes and authentication in memory.
 *
 * @author Ryan Heaton
 */
public class InMemoryVerificationCodeServices extends RandomValueVerificationCodeServices {

  protected final ConcurrentHashMap<String, OAuth2Authentication> verificationStore = new ConcurrentHashMap<String, OAuth2Authentication>();

  @Override
  protected void store(String code, OAuth2Authentication authentication) {
    this.verificationStore.put(code, authentication);
  }

  public OAuth2Authentication consumeVerificationCode(String code) throws InvalidVerificationCodeException {
    OAuth2Authentication auth = this.verificationStore.remove(code);
    if (auth == null) {
      throw new InvalidVerificationCodeException("Invalid verification code: " + code);
    }
    return auth;
  }
}
