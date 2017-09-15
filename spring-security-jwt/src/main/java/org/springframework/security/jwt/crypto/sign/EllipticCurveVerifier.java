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
package org.springframework.security.jwt.crypto.sign;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

/**
 * @author Michael Duergner
 */
public class EllipticCurveVerifier implements SignatureVerifier {

    private final ECPublicKey key;

    private final String algorithm;

    public EllipticCurveVerifier(final BigInteger x, final BigInteger y, final String curve, final String algorithm) {
        this(EllipticCurveKeyHelper.createPublicKey(x, y, curve), algorithm);
    }

    public EllipticCurveVerifier(final ECPublicKey key, final String algorithm) {
        this.key = key;
        this.algorithm = algorithm;
    }

    @Override
    public String algorithm() {
        return algorithm;
    }

    @Override
    public void verify(byte[] content, byte[] sig) {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(key);
            signature.update(content);

            if (!signature.verify(transcodeSignatureToDER(sig))) {
                throw new InvalidSignatureException("EC Signature did not match content");
            }
        }
        catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] transcodeSignatureToDER(byte[] jwsSignature) throws GeneralSecurityException {

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
