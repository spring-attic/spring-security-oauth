/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.jwt.crypto.sign;

import java.security.GeneralSecurityException;

/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) utilities.
 *
 * <p>
 * Borrowed from <code>com.nimbusds.jose.crypto.ECDSA</code>.
 */
final class EllipticCurveSignatureHelper {

	/**
	 * Transcodes the JCA ASN.1/DER-encoded signature into the concatenated
	 * R + S format expected by ECDSA JWS.
	 *
	 * @param derSignature The ASN.1/DER-encoded. Must not be {@code null}.
	 * @param outputLength The expected length of the ECDSA JWS signature.
	 *
	 * @return The ECDSA JWS encoded signature.
	 *
	 * @throws GeneralSecurityException If the ASN.1/DER signature format is invalid.
	 */
	static byte[] transcodeSignatureToJWS(final byte[] derSignature, int outputLength) throws GeneralSecurityException {

		if (derSignature.length < 8 || derSignature[0] != 48) {
			throw new GeneralSecurityException("Invalid ECDSA signature format");
		}

		int offset;
		if (derSignature[1] > 0) {
			offset = 2;
		} else if (derSignature[1] == (byte) 0x81) {
			offset = 3;
		} else {
			throw new GeneralSecurityException("Invalid ECDSA signature format");
		}

		byte rLength = derSignature[offset + 1];

		int i;
		for (i = rLength; (i > 0) && (derSignature[(offset + 2 + rLength) - i] == 0); i--) {
			// do nothing
		}

		byte sLength = derSignature[offset + 2 + rLength + 1];

		int j;
		for (j = sLength; (j > 0) && (derSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0); j--) {
			// do nothing
		}

		int rawLen = Math.max(i, j);
		rawLen = Math.max(rawLen, outputLength / 2);

		if ((derSignature[offset - 1] & 0xff) != derSignature.length - offset
				|| (derSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
				|| derSignature[offset] != 2
				|| derSignature[offset + 2 + rLength] != 2) {
			throw new GeneralSecurityException("Invalid ECDSA signature format");
		}

		final byte[] concatSignature = new byte[2 * rawLen];

		System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i);
		System.arraycopy(derSignature, (offset + 2 + rLength + 2 + sLength) - j, concatSignature, 2 * rawLen - j, j);

		return concatSignature;
	}

	/**
	 * Transcodes the ECDSA JWS signature into ASN.1/DER format for use by
	 * the JCA verifier.
	 *
	 * @param jwsSignature The JWS signature, consisting of the
	 *                     concatenated R and S values. Must not be
	 *                     {@code null}.
	 *
	 * @return The ASN.1/DER encoded signature.
	 *
	 * @throws GeneralSecurityException If the ECDSA JWS signature format is invalid.
	 */
	static byte[] transcodeSignatureToDER(byte[] jwsSignature) throws GeneralSecurityException {

		// Adapted from org.apache.xml.security.algorithms.implementations.SignatureECDSA

		int rawLen = jwsSignature.length / 2;

		int i;

		for (i = rawLen; (i > 0) && (jwsSignature[rawLen - i] == 0); i--) {
			// do nothing
		}

		int j = i;

		if (jwsSignature[rawLen - i] < 0) {
			j += 1;
		}

		int k;

		for (k = rawLen; (k > 0) && (jwsSignature[2 * rawLen - k] == 0); k--) {
			// do nothing
		}

		int l = k;

		if (jwsSignature[2 * rawLen - k] < 0) {
			l += 1;
		}

		int len = 2 + j + 2 + l;

		if (len > 255) {
			throw new GeneralSecurityException("Invalid ECDSA signature format");
		}

		int offset;

		final byte derSignature[];

		if (len < 128) {
			derSignature = new byte[2 + 2 + j + 2 + l];
			offset = 1;
		} else {
			derSignature = new byte[3 + 2 + j + 2 + l];
			derSignature[1] = (byte) 0x81;
			offset = 2;
		}

		derSignature[0] = 48;
		derSignature[offset++] = (byte) len;
		derSignature[offset++] = 2;
		derSignature[offset++] = (byte) j;

		System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

		offset += j;

		derSignature[offset++] = 2;
		derSignature[offset++] = (byte) l;

		System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

		return derSignature;
	}
}