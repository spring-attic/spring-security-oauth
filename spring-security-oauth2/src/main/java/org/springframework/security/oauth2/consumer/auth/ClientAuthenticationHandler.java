package org.springframework.security.oauth2.consumer.auth;

import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.consumer.OAuth2ProtectedResourceDetails;
import org.springframework.util.MultiValueMap;

/**
 * Logic for handling client authentication.
 *
 * @author Ryan Heaton
 */
public interface ClientAuthenticationHandler {

  /**
   * Authenticate a token request.
   *
   * @param resource The resource for which to authenticate a request.
   * @param form The form that is being submitted as the token request.
   * @param request The request.
   */
  void authenticateTokenRequest(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form, ClientHttpRequest request);
}
