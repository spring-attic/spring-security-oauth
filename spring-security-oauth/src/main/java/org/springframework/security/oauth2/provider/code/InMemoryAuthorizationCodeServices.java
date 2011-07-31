package org.springframework.security.oauth2.provider.code;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of authorization code services that stores the codes and authentication in memory.
 *
 * @author Ryan Heaton
 */
public class InMemoryAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

  protected final ConcurrentHashMap<String, OAuth2Authentication<? extends UnconfirmedAuthorizationCodeAuthenticationToken, ? extends Authentication>> authorizationCodeStore
    = new ConcurrentHashMap<String, OAuth2Authentication<? extends UnconfirmedAuthorizationCodeAuthenticationToken, ? extends Authentication>>();

  @Override
  protected void store(String code, OAuth2Authentication<? extends UnconfirmedAuthorizationCodeAuthenticationToken, ? extends Authentication> authentication) {
    this.authorizationCodeStore.put(code, authentication);
  }

  public OAuth2Authentication<? extends UnconfirmedAuthorizationCodeAuthenticationToken, ? extends Authentication> consumeAuthorizationCode(String code) throws InvalidGrantException  {
    OAuth2Authentication<? extends UnconfirmedAuthorizationCodeAuthenticationToken, ? extends Authentication> auth = this.authorizationCodeStore.remove(code);
    if (auth == null) {
      throw new InvalidGrantException("Invalid authorization code: " + code);
    }
    return auth;
  }
}
