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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

/**
 * Verifies signatures using an Elliptic Curve public key.
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Michael Duergner
 * @since 2.3
 */
@Deprecated
public class EllipticCurveVerifier implements SignatureVerifier {
	private final ECPublicKey key;
	private final String algorithm;

	public EllipticCurveVerifier(final BigInteger x, final BigInteger y,
								 final String curve, final String algorithm) {
		this(EllipticCurveKeyHelper.createPublicKey(x, y, curve), algorithm);
	}

	public EllipticCurveVerifier(final ECPublicKey key, final String algorithm) {
		this.key = key;
		this.algorithm = algorithm;
	}

	@Override
	public String algorithm() {
		return this.algorithm;
	}

	@Override
	public void verify(byte[] content, byte[] sig) {
		try {
			Signature signature = Signature.getInstance(this.algorithm);
			signature.initVerify(this.key);
			signature.update(content);

			if (!signature.verify(EllipticCurveSignatureHelper.transcodeSignatureToDER(sig))) {
				throw new InvalidSignatureException("EC Signature did not match content");
			}
		} catch (GeneralSecurityException ex) {
			throw new RuntimeException(ex);
		}
	}
}
