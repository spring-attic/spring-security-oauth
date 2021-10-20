/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.code;

import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.RequestTokenFactory;

import org.springframework.util.ClassUtils;
import redis.clients.jedis.JedisShardInfo;

/**
 * @author Stefan Rempfer
 */
public class RedisAuthorizationCodeServicesTests {

	private RedisAuthorizationCodeServices authorizationCodeServices;

	private OAuth2Authentication authentication;

	/**
	 * Initialize test data and Class-Under-Test.
	 */
	@Before
	public void setup() {
		boolean springDataRedis_2_0 = ClassUtils.isPresent(
				"org.springframework.data.redis.connection.RedisStandaloneConfiguration",
				this.getClass().getClassLoader());

		JedisConnectionFactory connectionFactory;
		if (springDataRedis_2_0) {
			connectionFactory = new JedisConnectionFactory();
		} else {
			JedisShardInfo shardInfo = new JedisShardInfo("localhost");
			connectionFactory = new JedisConnectionFactory(shardInfo);
		}

		authorizationCodeServices = new RedisAuthorizationCodeServices(connectionFactory);

		authentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("myClientId", false),
				new TestingAuthenticationToken("myUser4Test", false));
	}

	/**
	 * Verifies that a authorization code could be generated and stored.
	 */
	@Test
	public void verifyCreateAuthorizationCode() {
		String authorizationCode1 = authorizationCodeServices.createAuthorizationCode(authentication);
		assertNotNull("Authorization code must not be null!", authorizationCode1);

		String authorizationCode2 = authorizationCodeServices.createAuthorizationCode(authentication);
		assertNotNull("Authorization code must not be null!", authorizationCode2);

		assertNotEquals("Authorization code must be different!", authorizationCode1, authorizationCode2);
	}

	/**
	 * Verifies that a authorization code could be retrieved and removed.
	 */
	@Test
	public void verifyCreateAndConsumeAuthorizationCode() {

		String authorizationCode = authorizationCodeServices.createAuthorizationCode(authentication);
		assertNotNull("Authorization code must not be null!", authorizationCode);

		OAuth2Authentication authentication = authorizationCodeServices.consumeAuthorizationCode(authorizationCode);
		assertNotSame("Authentication object must not be the same!", this.authentication, authentication);
		assertEquals("Authentication object must equals to original one!", this.authentication, authentication);

		try {
			authorizationCodeServices.consumeAuthorizationCode(authorizationCode);
			fail("There must be an exception that the authorization code is invalid!");
		}
		catch (InvalidGrantException e) {
			assertThat("Wrong error message!", e.getMessage(),
					allOf(containsString("Invalid authorization code")));
		}
	}
}
