package org.springframework.security.oauth2.provider.verification;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of verification code services that stores the codes and authentication in memory.
 *
 * @author Ryan Heaton
 */
public class InMemoryVerificationCodeServices extends RandomValueVerificationCodeServices {

  protected final ConcurrentHashMap<String, OAuth2Authentication<? extends VerificationCodeAuthenticationToken, ? extends Authentication>> verificationStore
    = new ConcurrentHashMap<String, OAuth2Authentication<? extends VerificationCodeAuthenticationToken, ? extends Authentication>>();

  @Override
  protected void store(String code, OAuth2Authentication<? extends VerificationCodeAuthenticationToken, ? extends Authentication> authentication) {
    this.verificationStore.put(code, authentication);
  }

  public OAuth2Authentication<? extends VerificationCodeAuthenticationToken, ? extends Authentication> consumeVerificationCode(String code) throws InvalidGrantException  {
    OAuth2Authentication<? extends VerificationCodeAuthenticationToken, ? extends Authentication> auth = this.verificationStore.remove(code);
    if (auth == null) {
      throw new InvalidGrantException("Invalid verification code: " + code);
    }
    return auth;
  }
}
