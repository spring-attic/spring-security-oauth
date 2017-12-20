/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.jwt.crypto.sign;

import org.junit.Test;
import org.springframework.security.jwt.codec.Codecs;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * Tests for {@link EllipticCurveVerifier}.
 *
 * @author Joe Grandja
 */
public class EllipticCurveVerifierTests {
	private final static String P256_CURVE = "P-256";
	private final static String P384_CURVE = "P-384";
	private final static String P521_CURVE = "P-521";
	private final static String SHA256_ECDSA_ALG = "SHA256withECDSA";
	private final static String SHA384_ECDSA_ALG = "SHA384withECDSA";
	private final static String SHA512_ECDSA_ALG = "SHA512withECDSA";

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenUnsupportedCurveThenThrowIllegalArgumentException() {
		new EllipticCurveVerifier(BigInteger.ONE, BigInteger.ONE, "unsupported-curve", SHA256_ECDSA_ALG);
	}

	@Test
	public void verifyWhenP256CurveAndSignatureMatchesThenVerificationPasses() throws Exception {
		this.verifyWhenSignatureMatchesThenVerificationPasses(P256_CURVE, SHA256_ECDSA_ALG);
	}

	@Test(expected = InvalidSignatureException.class)
	public void verifyWhenP256CurveAndSignatureDoesNotMatchThenThrowInvalidSignatureException() throws Exception {
		this.verifyWhenSignatureDoesNotMatchThenThrowInvalidSignatureException(P256_CURVE, SHA256_ECDSA_ALG);
	}

	@Test
	public void verifyWhenP384CurveAndSignatureMatchesThenVerificationPasses() throws Exception {
		this.verifyWhenSignatureMatchesThenVerificationPasses(P384_CURVE, SHA384_ECDSA_ALG);
	}

	@Test(expected = InvalidSignatureException.class)
	public void verifyWhenP384CurveAndSignatureDoesNotMatchThenThrowInvalidSignatureException() throws Exception {
		this.verifyWhenSignatureDoesNotMatchThenThrowInvalidSignatureException(P384_CURVE, SHA384_ECDSA_ALG);
	}

	@Test
	public void verifyWhenP521CurveAndSignatureMatchesThenVerificationPasses() throws Exception {
		this.verifyWhenSignatureMatchesThenVerificationPasses(P521_CURVE, SHA512_ECDSA_ALG);
	}

	@Test(expected = InvalidSignatureException.class)
	public void verifyWhenP521CurveAndSignatureDoesNotMatchThenThrowInvalidSignatureException() throws Exception {
		this.verifyWhenSignatureDoesNotMatchThenThrowInvalidSignatureException(P521_CURVE, SHA512_ECDSA_ALG);
	}

	@Test(expected = InvalidSignatureException.class)
	public void verifyWhenSignatureAlgorithmNotSameAsVerificationAlgorithmThenThrowInvalidSignatureException() throws Exception {
		KeyPair keyPair = this.generateKeyPair(P256_CURVE);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		byte[] data = "Some data".getBytes();

		byte[] jwsSignature = Codecs.b64UrlEncode(this.generateJwsSignature(data, SHA256_ECDSA_ALG, privateKey));

		EllipticCurveVerifier verifier = new EllipticCurveVerifier(
				publicKey.getW().getAffineX(),
				publicKey.getW().getAffineY(),
				P256_CURVE,
				SHA512_ECDSA_ALG);
		verifier.verify(data, Codecs.b64UrlDecode(jwsSignature));
	}

	private void verifyWhenSignatureMatchesThenVerificationPasses(String curve, String algorithm) throws Exception {
		KeyPair keyPair = this.generateKeyPair(curve);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		byte[] data = "Some data".getBytes();

		byte[] jwsSignature = Codecs.b64UrlEncode(this.generateJwsSignature(data, algorithm, privateKey));

		EllipticCurveVerifier verifier = new EllipticCurveVerifier(
				publicKey.getW().getAffineX(),
				publicKey.getW().getAffineY(),
				curve,
				algorithm);
		verifier.verify(data, Codecs.b64UrlDecode(jwsSignature));
	}

	private void verifyWhenSignatureDoesNotMatchThenThrowInvalidSignatureException(String curve, String algorithm) throws Exception {
		KeyPair keyPair = this.generateKeyPair(curve);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		byte[] data = "Some data".getBytes();

		byte[] jwsSignature = Codecs.b64UrlEncode(this.generateJwsSignature(data, algorithm, privateKey));

		EllipticCurveVerifier verifier = new EllipticCurveVerifier(
				publicKey.getW().getAffineX(),
				publicKey.getW().getAffineY(),
				curve,
				algorithm);
		verifier.verify("Data not matching signature".getBytes(), Codecs.b64UrlDecode(jwsSignature));
	}

	private KeyPair generateKeyPair(String curve) throws Exception {
		ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(curve);
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA");
		keyPairGenerator.initialize(ecGenParameterSpec);
		return keyPairGenerator.generateKeyPair();
	}

	private byte[] generateJwsSignature(byte[] data, String algorithm, ECPrivateKey privateKey) throws Exception {
		Signature signature = Signature.getInstance(algorithm);
		signature.initSign(privateKey);
		signature.update(data);
		byte[] jcaSignature = signature.sign();// DER-encoded signature, according to JCA spec (sequence of two integers - R + S)
		int jwsSignatureLength = -1;
		if (SHA256_ECDSA_ALG.equals(algorithm)) {
			jwsSignatureLength = 64;
		} else if (SHA384_ECDSA_ALG.equals(algorithm)) {
			jwsSignatureLength = 96;
		} else if (SHA512_ECDSA_ALG.equals(algorithm)) {
			jwsSignatureLength = 132;
		}
		return EllipticCurveSignatureHelper.transcodeSignatureToJWS(jcaSignature, jwsSignatureLength);
	}
}
