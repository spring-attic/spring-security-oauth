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

import org.springframework.security.oauth.common.OAuthException;

/**
 * A service that provides the details about an oauth consumer.
 *
 * @author Ryan Heaton
 */
public interface ConsumerDetailsService {

  /**
   * Load a consumer by the consumer key. This method must NOT return null.
   *
   * @param consumerKey The consumer key.
   * @return The consumer details.
   * @throws OAuthException If the consumer account is locked, expired, disabled, or for any other reason.
   */
  ConsumerDetails loadConsumerByConsumerKey(String consumerKey) throws OAuthException;

}
