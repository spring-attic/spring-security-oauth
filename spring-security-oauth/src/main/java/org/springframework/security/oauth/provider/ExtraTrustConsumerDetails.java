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

/**
 * Consumer details for a specific resource.
 *
 * @author Ryan Heaton
 */
public interface ExtraTrustConsumerDetails extends ConsumerDetails {

  /**
   * Whether this consumer is required to obtain an authenticated oauth token. If <code>true</code>, it means that the OAuth consumer won't be granted access
   * to the protected resource unless the user is directed to the token authorization page. If <code>false</code>, it means that the provider has an additional
   * level of trust with the consumer.
   *
   * Not requiring an authenticated access token is also known as "2-legged" OAuth or "signed fetch".
   *
   * @return Whether this consumer is required to obtain an authenticated oauth token.
   */
  boolean isRequiredToObtainAuthenticatedToken();
}
