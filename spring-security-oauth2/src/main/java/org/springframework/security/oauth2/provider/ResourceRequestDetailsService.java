package org.springframework.security.oauth2.provider;

/**
 * Service to provide the details of a requested resource.
 *
 * @author Michael Kangas
 */
public interface ResourceRequestDetailsService {

  /**
   * Loads the details the requested resource by request method and resource URI.
   *
   * @param requestMethod the request method
   * @param resourceURI the URI of the requested resource
   * @return the details of the requested resource or {@code null} if none are found
   */
  ResourceRequestDetails loadResourceRequestDetails(String requestMethod, String resourceURI);

}