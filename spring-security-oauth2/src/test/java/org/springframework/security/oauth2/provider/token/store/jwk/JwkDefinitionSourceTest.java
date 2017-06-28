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

import org.apache.commons.codec.Charsets;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.jwt.codec.Codecs;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Arrays;
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

	@Test(expected = IllegalArgumentException.class)
	public void constructorListWhenInvalidJwkSetUrlThenThrowIllegalArgumentException() throws Exception {
		new JwkDefinitionSource(Arrays.asList(DEFAULT_JWK_SET_URL.substring(1)));
	}

	@Test
	public void getDefinitionLoadIfNecessaryWhenKeyIdNotFoundThenLoadJwkDefinitions() throws Exception {
		JwkDefinitionSource jwkDefinitionSource = spy(new JwkDefinitionSource(DEFAULT_JWK_SET_URL));
		mockStatic(JwkDefinitionSource.class);
		when(JwkDefinitionSource.loadJwkDefinitions(any(URL.class))).thenReturn(Collections.<String, JwkDefinitionSource.JwkDefinitionHolder>emptyMap());
		jwkDefinitionSource.getDefinitionLoadIfNecessary("invalid-key-id");
		verifyStatic();
	}

	// gh-1010
	@Test
	public void getVerifierWhenModulusMostSignificantBitIs1ThenVerifierStillVerifyContentSignature() throws Exception {
		String jwkSetUrl = JwkDefinitionSourceTest.class.getResource("jwk-set.json").toString();
		JwkDefinitionSource jwkDefinitionSource = new JwkDefinitionSource(jwkSetUrl);
		SignatureVerifier verifier = jwkDefinitionSource.getDefinitionLoadIfNecessary("_Ci3-VfV_N0YAG22NQOgOUpFBDDcDe_rJxpu5JK702o").getSignatureVerifier();
		String token = this.readToken("token.jwt");
		int secondPeriodIndex = token.indexOf('.', token.indexOf('.') + 1);
		String contentString = token.substring(0, secondPeriodIndex);
		byte[] content = contentString.getBytes(Charsets.UTF_8);
		String signatureString = token.substring(secondPeriodIndex + 1);
		byte[] signature = Codecs.b64UrlDecode(signatureString);
		verifier.verify(content, signature);
	}

	private String readToken(String resource) throws IOException {
		StringBuilder sb = new StringBuilder();
		InputStream in = null;
		try {
			in = JwkDefinitionSourceTest.class.getResourceAsStream(resource);
			int ch;
			while ((ch = in.read()) != -1) {
				sb.append((char) ch);
			}
		} finally {
			if (in != null) {
				in.close();
			}
		}
		return sb.toString();
	}
}