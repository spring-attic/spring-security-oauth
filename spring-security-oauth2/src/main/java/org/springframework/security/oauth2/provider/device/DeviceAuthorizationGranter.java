/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.device;

import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * Granter for device flow
 *
 * @author Bin Wang
 */
public class DeviceAuthorizationGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE="urn:ietf:params:oauth:grant-type:device_code";
    private DeviceAuthorizationCodeServices deviceAuthorizationCodeServices;

    public DeviceAuthorizationGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, DeviceAuthorizationCodeServices deviceAuthorizationCodeServices) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.deviceAuthorizationCodeServices=deviceAuthorizationCodeServices;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Map<String,String> parameters=tokenRequest.getRequestParameters();
        String deviceCode=parameters.get(OAuth2Utils.DEVICE_CODE);

        if(StringUtils.isEmpty(deviceCode)){
            throw new InvalidRequestException("An device code must be supplied.");
        }
        OAuth2Authentication storedAuth=deviceAuthorizationCodeServices.consumeByDeviceCode(deviceCode);
        if(storedAuth==null){
            throw new InvalidGrantException("Invalid device code: " + deviceCode);
        }
        String pendingClientId = storedAuth.getOAuth2Request().getClientId();
        String clientId=tokenRequest.getClientId();
        if (clientId != null && !clientId.equals(pendingClientId)) {
            throw new InvalidClientException("Client ID mismatch");
        }
        storedAuth.getOAuth2Request().getRequestParameters().put(OAuth2Utils.GRANT_TYPE,GRANT_TYPE);
        return storedAuth;
    }
}
