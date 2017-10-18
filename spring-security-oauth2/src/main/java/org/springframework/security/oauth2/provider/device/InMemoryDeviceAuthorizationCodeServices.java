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

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.StringUtils;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Default in memory device authorization code store
 *
 * @author Bin Wang
 */
public class InMemoryDeviceAuthorizationCodeServices extends RandomDeviceAuthorizationCodeServices {

    protected final ConcurrentHashMap<String, String> deviceUserCodeMapping=new ConcurrentHashMap<String, String>();

    protected final ConcurrentHashMap<String,OAuth2Authentication> codeStore=new ConcurrentHashMap<String, OAuth2Authentication>();


    @Override
    protected void store(OAuth2Authentication authentication, String userCode, String deviceCode) {
        deviceUserCodeMapping.put(deviceCode,userCode);
        codeStore.put(userCode,authentication);
    }

    @Override
    public OAuth2Authentication getByUserCode(String userCode) {
       return this.codeStore.get(userCode);
    }

    @Override
    protected OAuth2Authentication getByDeviceCode(String deviceCode) {
        String userCode=this.deviceUserCodeMapping.get(deviceCode);
        if(StringUtils.isEmpty(userCode))
            return null;
        else
            return getByUserCode(userCode);
    }

    @Override
    protected OAuth2Authentication remove(String deviceCode) {
        String userCode=this.deviceUserCodeMapping.remove(deviceCode);
        if(StringUtils.isEmpty(userCode))
            return null;
        else
            return codeStore.remove(deviceCode);
    }
}
