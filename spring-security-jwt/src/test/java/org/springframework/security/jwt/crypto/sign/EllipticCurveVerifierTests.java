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

import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.springframework.security.jwt.codec.Codecs;

import java.math.BigInteger;

/**
 * @author Michael Duergner
 */
public class EllipticCurveVerifierTests {

  private static final byte[] xBytes = Codecs.b64UrlDecode("IsxeG33-QlL2u-O38QKwAbw5tJTZ-jtMVSlzjNXhvys");
  private static final byte[] yBytes = Codecs.b64UrlDecode("FPTFJF1M0sNRlOVZIH4e1DoZ_hdg1OvF6BlP2QHmSCg");

  private final static BigInteger X = new BigInteger(1, xBytes);

  private final static BigInteger Y = new BigInteger(1, yBytes);

  private final static String CRV = "P-256";

  private final static String ALG = "SHA256withECDSA";

  @Test(expected = IllegalArgumentException.class)
  public void ellipticCurveVerifierRejectsUnknownCurve() {
    EllipticCurveVerifier verifier = new EllipticCurveVerifier(
        BigInteger.ONE,
        BigInteger.ONE,
        "xxx",
        null);
    assertNotNull(verifier);
  }

  @Test
  public void ellipticCurveVerifierValidWithEmptyAlgorithm() {
    EllipticCurveVerifier verifier = new EllipticCurveVerifier(
        EllipticCurveVerifierTests.X,
        EllipticCurveVerifierTests.Y,
        EllipticCurveVerifierTests.CRV,
        null);
    assertNotNull(verifier);
  }

  @Test
  public void keyFromCurveParametersIsCorrect() {
    byte[] sig = Codecs.b64UrlDecode(
        "gR2_00D_famhmT9h_7cQ7Sfi3J13nFUOH1PsC3WwgVdMV5yI6CXHHcybZKa266yckCGHS1MGKgp3pBsUv93P1Q");
    byte[] content = Codecs.utf8Encode("eyJhbGciOiJFUzI1NiJ9.eyJrZXkiOiJ2YWx1ZSJ9");

    EllipticCurveVerifier verifier = new EllipticCurveVerifier(
        EllipticCurveVerifierTests.X,
        EllipticCurveVerifierTests.Y,
        EllipticCurveVerifierTests.CRV,
        EllipticCurveVerifierTests.ALG);
    verifier.verify(content, sig);
  }

  @Test(expected = InvalidSignatureException.class)
  public void signatureIsNotValidForDifferentAlgorithm() {
    byte[] sig = Codecs.b64UrlDecode(
            "gR2_00D_famhmT9h_7cQ7Sfi3J13nFUOH1PsC3WwgVdMV5yI6CXHHcybZKa266yckCGHS1MGKgp3pBsUv93P1Q");
    byte[] content = Codecs.utf8Encode("eyJhbGciOiJFUzI1NiJ9.eyJrZXkiOiJ2YWx1ZSJ9");

    EllipticCurveVerifier verifier = new EllipticCurveVerifier(
        EllipticCurveVerifierTests.X,
        EllipticCurveVerifierTests.Y,
        EllipticCurveVerifierTests.CRV,
        "SHA512withECDSA");
    verifier.verify(content, sig);
  }

  @Test(expected = InvalidSignatureException.class)
  public void brokenSignatureIsNotValid() {
    byte[] sig = Codecs.b64UrlDecode(
            "fx2_00D_famhmT9h_7cQ7Sfi3J13nFUOH1PsC3WwgVdMV5yI6CXHHcybZKa266yckCGHS1MGKgp3pBsUv93P1Q");
    byte[] content = Codecs.utf8Encode("eyJhbGciOiJFUzI1NiJ9.eyJrZXkiOiJ2YWx1ZSJ9");

    EllipticCurveVerifier verifier = new EllipticCurveVerifier(
        EllipticCurveVerifierTests.X,
        EllipticCurveVerifierTests.Y,
        EllipticCurveVerifierTests.CRV,
        EllipticCurveVerifierTests.ALG);
    verifier.verify(content, sig);
  }
}
