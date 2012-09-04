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

package org.springframework.security.oauth2.client.token.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Map;

/**
 * Logic to validate a given OAuth2AccessToken and load an Authentication object for a client to use
 *
 * @author Vidya Valmikinathan
 */
public interface CheckTokenServices {

    /**
     * Load an authentication object from the given OAuth2AccessToken
     * @param accessToken
     * @return an Authentication object that can be set in the SecurityContext
     * @throws AuthenticationException
     */
    Authentication loadAuthentication (OAuth2AccessToken accessToken) throws AuthenticationException;

    /**
     * Load an authentication object from the given OAuth2AccessToken and a map of user-profile-info
     * @param accessToken
     * @param userInfo
     * @return an Authentication object that can be set in the SecurityContext
     * @throws AuthenticationException
     */
    Authentication loadAuthentication (OAuth2AccessToken accessToken, Map<String, String> userInfo) throws AuthenticationException;
}
