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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URL;
import java.util.Collections;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.*;


/**
 * @author Joe Grandja
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(JwkDefinitionSource.class)
public class JwkDefinitionSourceTest {
	private static final String DEFAULT_JWK_SET_URL = "https://identity.server1.io/token_keys";

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenInvalidJwkSetUrlThenThrowIllegalArgumentException() throws Exception {
		new JwkDefinitionSource(DEFAULT_JWK_SET_URL.substring(1));
	}

	@Test
	public void getDefinitionLoadIfNecessaryWhenKeyIdNotFoundThenLoadJwkDefinitions() throws Exception {
		JwkDefinitionSource jwkDefinitionSource = spy(new JwkDefinitionSource(DEFAULT_JWK_SET_URL));
		mockStatic(JwkDefinitionSource.class);
		when(JwkDefinitionSource.loadJwkDefinitions(any(URL.class))).thenReturn(Collections.<String, JwkDefinitionSource.JwkDefinitionHolder>emptyMap());
		jwkDefinitionSource.getDefinitionLoadIfNecessary("invalid-key-id");
		verifyStatic();
	}
}