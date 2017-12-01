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

import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.redis.JdkSerializationStrategy;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStoreSerializationStrategy;

import java.util.List;

/**
 * A device authorization code store service in Redis
 * @author Bin Wang
 */
public class RedisDeviceAuthorizationCodeServices extends RandomDeviceAuthorizationCodeServices {

    private final RedisConnectionFactory connectionFactory;
    private static final String DEVICE_USER_CODE_MAPPING="device_user_mapping:";
    private static final String CODE_STORE="device_code_store:";


    private RedisTokenStoreSerializationStrategy redisTokenStoreSerializationStrategy=new JdkSerializationStrategy();

    public RedisDeviceAuthorizationCodeServices(RedisConnectionFactory redisConnectionFactory){
        super();
        this.connectionFactory=redisConnectionFactory;
    }

    @Override
    protected void store(OAuth2Authentication authentication, String userCode, String deviceCode) {
        byte[] mappingKey=serializeString(DEVICE_USER_CODE_MAPPING+deviceCode);
        byte[] mappingValue=serializeString(userCode);
        byte[] storeKey=serializeString(CODE_STORE+userCode);
        byte[] storeValue=serializeCodeStore(authentication);
        RedisConnection connection=connectionFactory.getConnection();
        try{
            connection.openPipeline();
            connection.setEx(mappingKey,getExpiresIn(),mappingValue);
            connection.setEx(storeKey,getExpiresIn(),storeValue);
            connection.closePipeline();
        }finally {
            connection.close();
        }

    }

    @Override
    public OAuth2Authentication getByUserCode(String userCode) {
        byte[] storeKey=serializeString(CODE_STORE+userCode);
        RedisConnection connection=connectionFactory.getConnection();
        try{
            return deserializeCodeStore(connection.get(storeKey));
        }catch (Exception e){
        }
        finally {
            connection.close();
        }
        return null;
    }

    @Override
    protected OAuth2Authentication getByDeviceCode(String deviceCode) {
        byte[] mappingKey=serializeString(DEVICE_USER_CODE_MAPPING+deviceCode);

        RedisConnection connection=connectionFactory.getConnection();
        try{
            String userCode=deserializeMapping(connection.get(mappingKey));
            byte[] storeKey=serializeString(CODE_STORE+userCode);
            return deserializeCodeStore(connection.get(storeKey));
        }catch (Exception e){
        }
        finally {
            connection.close();
        }
        return null;
    }

    @Override
    protected OAuth2Authentication remove(String deviceCode) {
        byte[] mappingKey=serializeString(DEVICE_USER_CODE_MAPPING+deviceCode);
        List<Object> results=null;
        RedisConnection connection=connectionFactory.getConnection();
        try {
            String userCode = deserializeMapping(connection.get(mappingKey));
            if(userCode!=null) {
                byte[] storeKey = serializeString(CODE_STORE + userCode);
                connection.openPipeline();
                connection.get(storeKey);
                connection.del(mappingKey,storeKey);
                 results=connection.closePipeline();
            }

        }catch (Exception ex){}
        finally {
            connection.close();
        }
        if(results!=null && results.size()>0){
            try {
                return deserializeCodeStore((byte[]) results.get(0));
            }catch (Exception ex){

            }
        }
        return null;
    }

    private byte[] serializeString(String key){
        return redisTokenStoreSerializationStrategy.serialize(key);
    }
    private String deserializeMapping(byte[] userCodeValue){
        return redisTokenStoreSerializationStrategy.deserializeString(userCodeValue);
    }

    private byte[] serializeCodeStore(OAuth2Authentication authentication){
        return redisTokenStoreSerializationStrategy.serialize(authentication);
    }
    private OAuth2Authentication deserializeCodeStore(byte[] authBytes){
        return redisTokenStoreSerializationStrategy.deserialize(authBytes,OAuth2Authentication.class);
    }



    public void setRedisTokenStoreSerializationStrategy(RedisTokenStoreSerializationStrategy redisTokenStoreSerializationStrategy) {
        this.redisTokenStoreSerializationStrategy = redisTokenStoreSerializationStrategy;
    }
}
