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

package org.springframework.security.oauth.consumer.net;

import org.springframework.security.oauth.consumer.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.OAuthConsumerSupport;

import java.net.URLStreamHandler;
import java.util.Map;

/**
 * Factory for a OAuth URL stream handlers.
 *
 * @author Ryan Heaton
 */
public interface OAuthURLStreamHandlerFactory {

  /**
   * Get the handler for an HTTP stream.
   *
   * @param resourceDetails The resource details.
   * @param accessToken The access token.
   * @param support The logic support.
   * @param httpMethod The http method.
   * @param additionalParameters Additional parameters.
   * @return The stream handler.
   */
  URLStreamHandler getHttpStreamHandler(ProtectedResourceDetails resourceDetails, OAuthConsumerToken accessToken, OAuthConsumerSupport support, String httpMethod, Map<String, String> additionalParameters);

  /**
   * Get the handler for an HTTPS stream.
   *
   * @param resourceDetails The resource details.
   * @param accessToken The access token.
   * @param support The logic support.
   * @param httpMethod The http method.
   * @param additionalParameters Additional parameters.
   * @return The stream handler.
   */
  URLStreamHandler getHttpsStreamHandler(ProtectedResourceDetails resourceDetails, OAuthConsumerToken accessToken, OAuthConsumerSupport support, String httpMethod, Map<String, String> additionalParameters);
}
