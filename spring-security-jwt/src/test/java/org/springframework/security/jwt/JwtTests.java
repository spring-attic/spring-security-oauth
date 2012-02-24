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
package org.springframework.security.jwt;

import static org.junit.Assert.assertEquals;
import static org.springframework.security.jwt.JwtSpecData.*;

import org.junit.Test;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;

/**
 * @author Luke Taylor
 */
public class JwtTests {
	/**
	 * Sample from the JWT spec.
	 */
	static final String JOE_CLAIM_SEGMENT = "{\"iss\":\"joe\",\r\n" + " \"exp\":1300819380,\r\n" + " \"http://example.com/is_root\":true}";
	static final String JOE_HEADER_HMAC = "{\"typ\":\"JWT\",\r\n" + " \"alg\":\"HS256\"}";
	static final String JOE_HMAC_TOKEN = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." + "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	static final String JOE_RSA_TOKEN = "eyJhbGciOiJSUzI1NiJ9." + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." + "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds" + "9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZR" + "mB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs9" + "8rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
	static final String JOE_HEADER_RSA = "{\"alg\":\"RS256\"}";
	static final MacSigner hmac = new MacSigner(JwtSpecData.HMAC_KEY);

	@Test
	public void tokenBytesCreateSameToken() throws Exception {
		Jwt token = JwtHelper.decode(JOE_HMAC_TOKEN);
		assertEquals(JOE_HMAC_TOKEN, new String(token.bytes(), "UTF-8"));
		assertEquals(JOE_HMAC_TOKEN, token.getEncoded());
	}

	@Test
	public void expectedClaimsValueIsReturned() {
		assertEquals(JOE_CLAIM_SEGMENT, JwtHelper.decode(JOE_HMAC_TOKEN).getClaims());
	}

	@Test
	public void hmacSignedTokenParsesAndVerifies() {
		JwtHelper.decode(JOE_HMAC_TOKEN).verifySignature(hmac);
	}

	@Test(expected=InvalidSignatureException.class)
	public void invalidHmacSignatureRaisesException() {
		JwtHelper.decode(JOE_HMAC_TOKEN).verifySignature(new MacSigner("differentkey".getBytes()));
	}

	@Test(expected = IllegalArgumentException.class)
	public void tokenMissingSignatureIsRejected() {
		JwtHelper.decode(JOE_HMAC_TOKEN.substring(0, JOE_HMAC_TOKEN.lastIndexOf('.') + 1));
	}

	@Test
	public void hmacVerificationIsInverseOfSigning() {
		Jwt jwt = JwtHelper.encode(JOE_CLAIM_SEGMENT, hmac);
		jwt.verifySignature(hmac);
		assertEquals (JOE_CLAIM_SEGMENT, jwt.getClaims());
	}

	@Test
	public void rsaSignedTokenParsesAndVerifies() {
		Jwt jwt = JwtHelper.decode(JOE_RSA_TOKEN);
		jwt.verifySignature(new RsaVerifier(N, E));
		assertEquals(JOE_CLAIM_SEGMENT, jwt.getClaims());
	}

	@Test(expected = InvalidSignatureException.class)
	public void invalidRsaSignatureRaisesException() {
		JwtHelper.decodeAndVerify(JOE_RSA_TOKEN, new RsaVerifier(N, D));
	}

	@Test
	public void rsaVerificationIsInverseOfSigning() {
		Jwt jwt = JwtHelper.encode(JOE_CLAIM_SEGMENT, new RsaSigner(N, E));
		jwt.verifySignature(new RsaVerifier(N, D));
	}
}


