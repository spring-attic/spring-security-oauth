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

import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;

/**
 *  This is for user grant successfully display in /oauth/error
 *
 * @author Bin Wang
 */

public class UserGrantSuccessException extends ClientAuthenticationException {

    public UserGrantSuccessException(String msg, Throwable t) {
        super(msg, t);
    }

    public UserGrantSuccessException(String msg) {
        super(msg);
    }

    @Override
    public String getOAuth2ErrorCode() {
        return "authorization_successful";
    }
}
