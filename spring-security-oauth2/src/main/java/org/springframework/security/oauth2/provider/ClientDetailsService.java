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

package org.springframework.security.oauth2.provider;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * A service that provides the details about an oauth consumer.
 *
 * @author Ryan Heaton
 */
public interface ClientDetailsService {

  /**
   * Load a client by the client id. This method must NOT return null.
   *
   * @param clientId The client id.
   * @return The client details.
   * @throws OAuth2Exception If the client account is locked, expired, disabled, or for any other reason.
   */
  ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception;

}