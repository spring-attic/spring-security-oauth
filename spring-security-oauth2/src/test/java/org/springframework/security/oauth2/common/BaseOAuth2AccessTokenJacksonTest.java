/*
 * Copyright 2006-2010 the original author or authors.
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
package org.springframework.security.oauth2.common;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 * Base class for testing Jackson serialization and deserialization of {@link OAuth2AccessToken}.
 *
 * @author Rob Winch
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ System.class })
abstract class BaseOAuth2AccessTokenJacksonTest {
	protected static final String ACCESS_TOKEN_EMPTYSCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"\"}";

	protected static final String ACCESS_TOKEN_BROKENEXPIRES = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":\"10\",\"scope\":\"\"}";

	protected static final String ACCESS_TOKEN_MULTISCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"read write\"}";

	protected static final String ACCESS_TOKEN_NOSCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10}";

	protected static final String ACCESS_TOKEN_NOREFRESH = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"expires_in\":10}";

	protected static final String ACCESS_TOKEN_SINGLESCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"write\"}";

	protected static final String ACCESS_TOKEN_ADDITIONAL_INFO = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"one\":\"two\",\"three\":4,\"five\":{\"six\":7}}";

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Mock
	protected Date expiration;

	protected DefaultOAuth2AccessToken accessToken;

	protected Map<String, Object> additionalInformation;

	public BaseOAuth2AccessTokenJacksonTest() {
		super();
	}

	@Before
	public void setUp() {
		mockStatic(System.class);
		long now = 1323123715041L;
		when(System.currentTimeMillis()).thenReturn(now);
		when(expiration.before(any(Date.class))).thenReturn(false);
		when(expiration.getTime()).thenReturn(now + 10000);

		accessToken = new DefaultOAuth2AccessToken("token-value");
		accessToken.setExpiration(expiration);
		DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken("refresh-value");
		accessToken.setRefreshToken(refreshToken);
		Set<String> scope = new TreeSet<String>();
		scope.add("read");
		scope.add("write");
		accessToken.setScope(scope);
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		map.put("one", "two");
		map.put("three", 4);
		map.put("five", Collections.singletonMap("six", 7));
		additionalInformation = map;
	}
}