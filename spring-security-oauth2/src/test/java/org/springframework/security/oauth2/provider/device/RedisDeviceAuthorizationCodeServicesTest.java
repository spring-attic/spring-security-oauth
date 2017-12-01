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

import org.junit.Before;
import org.junit.Test;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import redis.clients.jedis.JedisShardInfo;

import static org.junit.Assert.*;

/**
 * JUnit test for RedisDeviceAuthorizationCodeServices
 *
 * @author Bin Wang
 */
public class RedisDeviceAuthorizationCodeServicesTest {


    private DeviceAuthorizationCodeServices service;

    @Before
    public void init(){
        JedisShardInfo shardInfo = new JedisShardInfo("localhost");
        JedisConnectionFactory connectionFactory = new JedisConnectionFactory(shardInfo);
        service=new RedisDeviceAuthorizationCodeServices(connectionFactory);

    }



    @Test
    public void happy() throws Exception {
        OAuth2Request request=RequestTokenFactory.createOAuth2Request("my-test-client",false);
        String[] codes=service.createAuthorizationCodes(request);

        try{
            OAuth2Authentication check=service.consumeByDeviceCode(codes[1]);
            fail("Should wait for user authorization");
        }catch (AuthorizationPendingException ex){

        }

        Authentication authentication=new TestingAuthenticationToken("my-test-user",null);
        OAuth2Authentication auth=service.grantByUserCode(request,codes[0],authentication);

        OAuth2Authentication fetch=service.consumeByDeviceCode(codes[1]);

        assertNotNull("The OAuth2Authentication can be consume by device code",fetch);
        assertEquals("Client id should be same as before",fetch.getOAuth2Request().getClientId(),request.getClientId());
        assertEquals("Principle should be same as before",fetch.getUserAuthentication().getPrincipal(),authentication.getPrincipal());
        try {
            OAuth2Authentication fetch2 = service.consumeByDeviceCode(codes[1]);
            fail("OAuth2Authentication can not be consumed twice");
        }catch (InvalidGrantException e){

        }
    }

}