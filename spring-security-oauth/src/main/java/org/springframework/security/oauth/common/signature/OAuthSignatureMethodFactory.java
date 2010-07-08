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

package org.springframework.security.oauth.common.signature;

/**
 * Factory for signature methods.
 *
 * @author Ryan Heaton
 */
public interface OAuthSignatureMethodFactory {

  /**
   * Get the signature method of the given name.
   *
   * @param methodName      The method name.
   * @param signatureSecret The signature secret.
   * @param tokenSecret     The token secret.
   * @return the signature method.
   * @throws UnsupportedSignatureMethodException
   *          If the specified signature method name isn't recognized or supported.
   */
  OAuthSignatureMethod getSignatureMethod(String methodName, SignatureSecret signatureSecret, String tokenSecret) throws UnsupportedSignatureMethodException;
}
