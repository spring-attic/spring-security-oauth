/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.consumer;


import java.net.URL;
import java.io.InputStream;
import java.util.Map;

/**
 * Consumer-side support for OAuth.
 *
 * @author Ryan Heaton
 */
public interface OAuthConsumerSupport {

  /**
   * Get an unauthorized request token for a protected resource.
   *
   * @param resourceId The id of the protected resource for which to get a consumer token.
   * @param callback The callback URL.
   * @return The unauthorized request token.
   */
  OAuthConsumerToken getUnauthorizedRequestToken(String resourceId, String callback) throws OAuthRequestFailedException;

  /**
   * Get an unauthorized request token for a protected resource.
   *
   * @param resource The protected resource for which to get a consumer token.
   * @param callback The callback URL.
   * @return The unauthorized request token.
   */
  OAuthConsumerToken getUnauthorizedRequestToken(ProtectedResourceDetails resource, String callback) throws OAuthRequestFailedException;

  /**
   * Get an access token for a protected resource.
   *
   * @param requestToken The (presumably authorized) request token.
   * @param verifier The token verifier.
   * @return The access token.
   */
  OAuthConsumerToken getAccessToken(OAuthConsumerToken requestToken, String verifier) throws OAuthRequestFailedException;

  /**
   * Get an access token for a protected resource.
   *
   * @param resource The resource for which to get the access token.
   * @param requestToken The (presumably authorized) request token.
   * @param verifier The token verifier.
   * @return The access token.
   */
  OAuthConsumerToken getAccessToken(ProtectedResourceDetails resource, OAuthConsumerToken requestToken, String verifier);

  /**
   * Read a protected resource from the given URL using the specified access token and HTTP method.
   *
   * @param url The URL.
   * @param accessToken The access token.
   * @param httpMethod The HTTP method.
   * @return The protected resource.
   */
  InputStream readProtectedResource(URL url, OAuthConsumerToken accessToken, String httpMethod) throws OAuthRequestFailedException;

  /**
   * Create a configured URL.  If the HTTP method to access the resource is "POST" or "PUT" and the "Authorization"
   * header isn't supported, then the OAuth parameters will be expected to be sent in the body of the request. Otherwise,
   * you can assume that the given URL is ready to be used without further work.
   *
   * @param url         The base URL.
   * @param accessToken The access token.
   * @param httpMethod The HTTP method.
   * @param additionalParameters Any additional request parameters.
   * @return The configured URL.
   */
  URL configureURLForProtectedAccess(URL url, OAuthConsumerToken accessToken, String httpMethod, Map<String, String> additionalParameters) throws OAuthRequestFailedException;

  /**
   * Get the authorization header using the given access token that should be applied to the specified URL.
   *
   * @param details     The details of the protected resource.
   * @param accessToken The access token.
   * @param url         The URL of the request.
   * @param httpMethod  The http method for the protected resource.
   * @param additionalParameters Any additional request parameters.
   * @return The authorization header, or null if the authorization header isn't supported by the provider of this resource.
   */
  String getAuthorizationHeader(ProtectedResourceDetails details, OAuthConsumerToken accessToken, URL url, String httpMethod, Map<String, String> additionalParameters);

  /**
   * Get the query string that is to be used in the given request. The query string will
   * include any custom query parameters in the URL and any necessary OAuth parameters.  Note,
   * however, that an OAuth parameter is not considered "necessary" if the provider of the resource
   * supports the authorization header.
   *
   * Any OAuth parameters will be URL-encoded, but not oauth-encoded, per the OAuth spec. 
   *
   * The query string is to be used by either applying it to the URL (for HTTP GET) or putting it
   * in the body of the request (for HTTP POST).
   *
   * @param details The resource details.
   * @param accessToken The access token.
   * @param url The URL
   * @param httpMethod The http method.
   * @param additionalParameters Any additional OAuth request parameters.
   * @return The query string.
   */
  String getOAuthQueryString(ProtectedResourceDetails details, OAuthConsumerToken accessToken, URL url, String httpMethod, Map<String, String> additionalParameters);
}
