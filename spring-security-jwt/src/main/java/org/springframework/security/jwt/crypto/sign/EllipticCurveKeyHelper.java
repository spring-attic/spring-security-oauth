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

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

/**
 * @author Michael Duergner
 */
class EllipticCurveKeyHelper {

    static ECPublicKey createPublicKey(final BigInteger x, final BigInteger y, final String curve) {
        try {
            ECNamedCurveParameterSpec curveParameterSpec = ECNamedCurveTable.getParameterSpec(curve);
            ECParameterSpec parameterSpec = new ECNamedCurveSpec(
                    curveParameterSpec.getName(),
                    curveParameterSpec.getCurve(),
                    curveParameterSpec.getG(),
                    curveParameterSpec.getN());
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(new ECPoint(x, y), parameterSpec);

            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
        }
        catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
