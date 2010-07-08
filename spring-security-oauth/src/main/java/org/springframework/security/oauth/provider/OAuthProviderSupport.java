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

package org.springframework.security.oauth.provider;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Support logic for OAuth providers.
 * 
 * @author Ryan Heaton
 */
public interface OAuthProviderSupport {
  
  /**
   * Parse the oauth consumer paramters from an HttpServletRequest. The parameters are to be decoded per the OAuth spec.
   *
   * @param request The servlet request.
   * @return The parsed parameters.
   */
  Map<String, String> parseParameters(HttpServletRequest request);

  /**
   * Get the signature base string for the specified request, per OAuth Core 1.0, 9.1
   *
   * @param request The request.
   * @return The signature base string.
   */
  String getSignatureBaseString(HttpServletRequest request);
}
