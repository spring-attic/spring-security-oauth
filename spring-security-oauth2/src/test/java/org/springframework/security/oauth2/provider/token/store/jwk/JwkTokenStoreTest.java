/*
 * Copyright 2012-2016 the original author or authors.
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
package org.springframework.security.oauth2.provider.token.store.jwk;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * @author jgrandja
 */
public class JwkTokenStoreTest {
	private JwkTokenStore jwkTokenStore = new JwkTokenStore("https://identity.server1.io/token_keys");

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Before
	public void setUp() throws Exception {
		this.thrown.expect(JwkException.class);
		this.thrown.expectMessage("This operation is not supported.");
	}

	@Test
	public void storeAccessTokenWhenCalledThenThrowJwkException() throws Exception {
		this.jwkTokenStore.storeAccessToken(null, null);
	}

	@Test
	public void removeAccessTokenWhenCalledThenThrowJwkException() throws Exception {
		this.jwkTokenStore.removeAccessToken(null);
	}

	@Test
	public void storeRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
		this.jwkTokenStore.storeRefreshToken(null, null);
	}

	@Test
	public void readRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
		this.jwkTokenStore.readRefreshToken(null);
	}

	@Test
	public void readAuthenticationForRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
		this.jwkTokenStore.readAuthenticationForRefreshToken(null);
	}

	@Test
	public void removeRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
		this.jwkTokenStore.removeRefreshToken(null);
	}

	@Test
	public void removeAccessTokenUsingRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
		this.jwkTokenStore.removeAccessTokenUsingRefreshToken(null);
	}

	@Test
	public void getAccessTokenWhenCalledThenThrowJwkException() throws Exception {
		this.jwkTokenStore.getAccessToken(null);
	}

	@Test
	public void findTokensByClientIdAndUserNameWhenCalledThenThrowJwkException() throws Exception {
		this.jwkTokenStore.findTokensByClientIdAndUserName(null, null);
	}

	@Test
	public void findTokensByClientIdWhenCalledThenThrowJwkException() throws Exception {
		this.jwkTokenStore.findTokensByClientId(null);
	}
}