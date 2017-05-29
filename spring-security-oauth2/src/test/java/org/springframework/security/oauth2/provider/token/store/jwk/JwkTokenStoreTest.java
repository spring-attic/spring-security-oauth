/*
 * Copyright 2012-2017 the original author or authors.
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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;
import static org.powermock.api.mockito.PowerMockito.spy;


/**
 * @author Joe Grandja
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(JwkTokenStore.class)
public class JwkTokenStoreTest {
	private JwkTokenStore jwkTokenStore = new JwkTokenStore("https://identity.server1.io/token_keys");

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void readAuthenticationUsingOAuth2AccessTokenWhenCalledThenDelegateCalled() throws Exception {
		JwkTokenStore spy = spy(this.jwkTokenStore);
		JwtTokenStore delegate = mock(JwtTokenStore.class);
		when(delegate.readAuthentication(any(OAuth2AccessToken.class))).thenReturn(null);

		Field field = ReflectionUtils.findField(spy.getClass(), "delegate");
		field.setAccessible(true);
		ReflectionUtils.setField(field, spy, delegate);

		spy.readAuthentication(mock(OAuth2AccessToken.class));
		verify(delegate).readAuthentication(any(OAuth2AccessToken.class));
	}

	@Test
	public void readAuthenticationUsingAccessTokenStringWhenCalledThenDelegateCalled() throws Exception {
		JwkTokenStore spy = spy(this.jwkTokenStore);
		JwtTokenStore delegate = mock(JwtTokenStore.class);
		when(delegate.readAuthentication(anyString())).thenReturn(null);

		Field field = ReflectionUtils.findField(spy.getClass(), "delegate");
		field.setAccessible(true);
		ReflectionUtils.setField(field, spy, delegate);

		spy.readAuthentication(anyString());
		verify(delegate).readAuthentication(anyString());
	}

	@Test
	public void readAccessTokenWhenCalledThenDelegateCalled() throws Exception {
		JwkTokenStore spy = spy(this.jwkTokenStore);
		JwtTokenStore delegate = mock(JwtTokenStore.class);
		when(delegate.readAccessToken(anyString())).thenReturn(null);

		Field field = ReflectionUtils.findField(spy.getClass(), "delegate");
		field.setAccessible(true);
		ReflectionUtils.setField(field, spy, delegate);

		spy.readAccessToken(anyString());
		verify(delegate).readAccessToken(anyString());
	}

	@Test
	public void removeAccessTokenWhenCalledThenDelegateCalled() throws Exception {
		JwkTokenStore spy = spy(this.jwkTokenStore);
		JwtTokenStore delegate = mock(JwtTokenStore.class);

		doNothing().when(delegate).removeAccessToken(any(OAuth2AccessToken.class));

		Field field = ReflectionUtils.findField(spy.getClass(), "delegate");
		field.setAccessible(true);
		ReflectionUtils.setField(field, spy, delegate);

		spy.removeAccessToken(any(OAuth2AccessToken.class));
		verify(delegate).removeAccessToken(any(OAuth2AccessToken.class));
	}

	@Test
	public void storeAccessTokenWhenCalledThenThrowJwkException() throws Exception {
		this.setUpExpectedJwkException();
		this.jwkTokenStore.storeAccessToken(null, null);
	}

	@Test
	public void storeRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
		this.setUpExpectedJwkException();
		this.jwkTokenStore.storeRefreshToken(null, null);
	}

	@Test
	public void readRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
		this.setUpExpectedJwkException();
		this.jwkTokenStore.readRefreshToken(null);
	}

	@Test
	public void readAuthenticationForRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
		this.setUpExpectedJwkException();
		this.jwkTokenStore.readAuthenticationForRefreshToken(null);
	}

	@Test
	public void removeRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
		this.setUpExpectedJwkException();
		this.jwkTokenStore.removeRefreshToken(null);
	}

	@Test
	public void removeAccessTokenUsingRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
		this.setUpExpectedJwkException();
		this.jwkTokenStore.removeAccessTokenUsingRefreshToken(null);
	}

	@Test
	public void getAccessTokenWhenCalledThenThrowJwkException() throws Exception {
		this.setUpExpectedJwkException();
		this.jwkTokenStore.getAccessToken(null);
	}

	@Test
	public void findTokensByClientIdAndUserNameWhenCalledThenThrowJwkException() throws Exception {
		this.setUpExpectedJwkException();
		this.jwkTokenStore.findTokensByClientIdAndUserName(null, null);
	}

	@Test
	public void findTokensByClientIdWhenCalledThenThrowJwkException() throws Exception {
		this.setUpExpectedJwkException();
		this.jwkTokenStore.findTokensByClientId(null);
	}

	private void setUpExpectedJwkException() {
		this.thrown.expect(JwkException.class);
		this.thrown.expectMessage("This operation is not supported.");
	}
}