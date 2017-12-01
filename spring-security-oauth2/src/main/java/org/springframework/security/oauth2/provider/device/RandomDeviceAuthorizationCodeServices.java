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
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.security.SecureRandom;

/**
 *  Abstract class of managing the device code and user code authorization service. It will generate a user friendly user code
 *  and a complex random string for device code.
 *
 *  @@author Bin Wang
 */
public abstract class RandomDeviceAuthorizationCodeServices implements DeviceAuthorizationCodeServices {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    private int expires_in=300;

    protected abstract void store(OAuth2Authentication authentication, String userCode, String deviceCode);

    public   abstract OAuth2Authentication getByUserCode(String userCode);

    protected abstract OAuth2Authentication getByDeviceCode(String deviceCode);

    protected abstract OAuth2Authentication remove(String deviceCode);

    @Override
    public String[] createAuthorizationCodes(OAuth2Request request) {
        String deviceCode=generator.generate();
        String userCode=String.format("%06d",Math.abs(new SecureRandom().nextInt()%1000000)); //simple 6 numeric characters for easier user input
        request.getExtensions().put("device_code",deviceCode);
        request.getExtensions().put("user_code",userCode);
        OAuth2Authentication authentication=new OAuth2Authentication(request,null);
        store(authentication,userCode,deviceCode);
        return new String[]{userCode,deviceCode};
    }

    @Override
    public OAuth2Authentication grantByUserCode(OAuth2Request request,String userCode, Authentication userAuth) throws InvalidGrantException {
        OAuth2Authentication authentication=getByUserCode(userCode);
        if(authentication==null){
            throw new InvalidGrantException("Invalid user code:"+ userCode);
        }
        authentication=new OAuth2Authentication(request,userAuth);
        store(authentication,userCode,String.valueOf(authentication.getOAuth2Request().getExtensions().get("device_code")));
        return authentication;
    }

    @Override
    public OAuth2Authentication consumeByDeviceCode(String deviceCode) throws InvalidGrantException, AuthorizationPendingException {
        OAuth2Authentication auth = this.getByDeviceCode(deviceCode);
        if (auth == null) {
            throw new InvalidGrantException("Invalid device code: " + deviceCode);
        }
        if(auth.getUserAuthentication()==null)
        {
            throw new AuthorizationPendingException("Waiting for user grant");
        }
        return remove(deviceCode);
    }

    @Override
    public int getExpiresIn() {
        return expires_in;
    }

    @Override
    public void setExpiresIn(int expires_in) {
        this.expires_in = expires_in;
    }
}
