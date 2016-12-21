/*
 * Copyright 2006-2016 the original author or authors.
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
package org.springframework.security.oauth2.provider.code;

import java.util.List;

import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.store.redis.JdkSerializationStrategy;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStoreSerializationStrategy;

/**
 * Implementation of authorization code services that stores the codes and authentication in Redis.
 * 
 * @author Stefan Rempfer
 */
public class RedisAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

	private static final String AUTH_CODE = "auth_code:";

	private final RedisConnectionFactory connectionFactory;

	private String prefix = "";

	private RedisTokenStoreSerializationStrategy serializationStrategy = new JdkSerializationStrategy();

	/**
	 * Default constructor.
	 *
	 * @param connectionFactory the connection factory which should be used to obtain a connection to Redis
	 */
	public RedisAuthorizationCodeServices(RedisConnectionFactory connectionFactory) {
		this.connectionFactory = connectionFactory;
	}

	@Override
	protected void store(String code, OAuth2Authentication authentication) {
		byte[] key = serializeKey(AUTH_CODE + code);
		byte[] auth = serialize(authentication);

		RedisConnection conn = getConnection();
		try {
			conn.set(key, auth);
		}
		finally {
			conn.close();
		}
	}

	@Override
	protected OAuth2Authentication remove(String code) {
		byte[] key = serializeKey(AUTH_CODE + code);

		List<Object> results = null;
		RedisConnection conn = getConnection();
		try {
			conn.openPipeline();
			conn.get(key);
			conn.del(key);
			results = conn.closePipeline();
		}
		finally {
			conn.close();
		}

		if (results == null) {
			return null;
		}
		byte[] bytes = (byte[]) results.get(0);
		return deserializeAuthentication(bytes);
	}

	private byte[] serializeKey(String object) {
		return serialize(prefix + object);
	}

	private byte[] serialize(Object object) {
		return serializationStrategy.serialize(object);
	}

	private byte[] serialize(String string) {
		return serializationStrategy.serialize(string);
	}

	private RedisConnection getConnection() {
		return connectionFactory.getConnection();
	}

	private OAuth2Authentication deserializeAuthentication(byte[] bytes) {
		return serializationStrategy.deserialize(bytes, OAuth2Authentication.class);
	}

	public void setSerializationStrategy(RedisTokenStoreSerializationStrategy serializationStrategy) {
		this.serializationStrategy = serializationStrategy;
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

}
