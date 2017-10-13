/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */


package org.springframework.security.oauth2.provider.device;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 * Interface of services for generating, store, granting and verify device code authorization
 *  https://tools.ietf.org/html/draft-ietf-oauth-device-flow-06
 *
 *  @author Bin Wang
 */
public interface DeviceAuthorizationCodeServices {

    /**
     * Generate a device_code and user_code from device authorize request
     * @param request
     * @return [user_code, device_code]
     */
   String[] createAuthorizationCodes(OAuth2Request request);

    /**
     * Grant the authorization by user, attach granted user authentication to the stored OAuth2Authentication object
     * if user_code matches
     * @param userCode user_code
     * @param userAuth user granted authentication
     * @return Updated OAuth2Authentication object
     * @throws InvalidGrantException code expires or invalid
     */
   OAuth2Authentication grantByUserCode(String userCode, Authentication userAuth) throws InvalidGrantException;;

    /**
     * Device fetch the granted OAuth2Authentication if deviceCode match and already granted
     * @param deviceCode device_code
     * @return granted OAuth2Authentication for token generating
     * @throws InvalidGrantException code expires or invalid
     * @throws AuthorizationPendingException authorization is pending by user
     */
   OAuth2Authentication consumeByDeviceCode(String deviceCode) throws InvalidGrantException, AuthorizationPendingException;

}
