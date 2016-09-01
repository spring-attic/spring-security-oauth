package org.springframework.security.oauth2.provider;

import java.util.Set;

/**
 * The details of a requested resource.
 *
 * @author Michael Kangas
 */
public interface ResourceRequestDetails {
  /**
   * The scope required for the resource request.
   *
   * @return set of scopes required for the resource request; empty if no scope is required
   */
  Set<String> getScope();

  /**
   * The request method.
   *
   * @return the request method
   */
  String getMethod();

  /**
   * The resource URI.
   *
   * @return the resource URI
   */
  String getURI();
}
