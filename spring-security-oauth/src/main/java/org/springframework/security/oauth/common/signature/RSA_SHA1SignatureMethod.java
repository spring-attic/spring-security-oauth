/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.common.signature;

import org.apache.commons.codec.binary.Base64;

import java.io.UnsupportedEncodingException;
import java.security.*;

/**
 * RSA-SHA1 signature method. The RSA-SHA1 signature method uses the RSASSA-PKCS1-v1_5 signature algorithm as defined in RFC3447
 * section 8.2 (more simply known as PKCS#1), using SHA-1 as the hash function for EMSA-PKCS1-v1_5.
 *
 * @author Ryan Heaton
 */
public class RSA_SHA1SignatureMethod implements OAuthSignatureMethod {

  /**
   * The name of this RSA-SHA1 signature method ("RSA-SHA1").
   */
  public static final String SIGNATURE_NAME = "RSA-SHA1";

  private final PrivateKey privateKey;
  private final PublicKey publicKey;

  /**
   * Construct a RSA-SHA1 signature method with the given RSA-SHA1 public/private key pair.
   *
   * @param privateKey The private key.
   * @param publicKey  The public key.
   */
  public RSA_SHA1SignatureMethod(PrivateKey privateKey, PublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Construct a RSA-SHA1 signature method with the given RSA-SHA1 private key.  This constructor is to be
   * used by the consumer (who has access to its own private key).
   *
   * @param key The key.
   */
  public RSA_SHA1SignatureMethod(PrivateKey key) {
    this(key, null);
  }

  /**
   * Construct a RSA-SHA1 signature method with the given RSA-SHA1 public key.  This constructor is to be
   * used by the provider (who has access to the public key of the consumer).
   *
   * @param key The key.
   */
  public RSA_SHA1SignatureMethod(PublicKey key) {
    this(null, key);
  }

  /**
   * The name of this RSA-SHA1 signature method ("RSA-SHA1").
   *
   * @return The name of this RSA-SHA1 signature method.
   */
  public String getName() {
    return SIGNATURE_NAME;
  }

  /**
   * The Signature Base String is signed using the Consumer’s RSA private key per RFC3447 section 8.2.1, where K is the Consumer’s RSA private key,
   * M the Signature Base String, and S is the result signature octet string:
   *
   * {@code S = RSASSA-PKCS1-V1_5-SIGN (K, M) }
   *
   * oauth_signature is set to S, first base64-encoded per RFC2045 section 6.8, then URL-encoded per Parameter Encoding.
   *
   * @param signatureBaseString The signature base string.
   * @return The signature.
   * @throws UnsupportedOperationException If there is no private key.
   */
  public String sign(String signatureBaseString) {
    if (privateKey == null) {
      throw new UnsupportedOperationException("Cannot sign the base string: no private key supplied.");
    }

    try {
      Signature signer = Signature.getInstance("SHA1withRSA");
      signer.initSign(privateKey);
      signer.update(signatureBaseString.getBytes("UTF-8"));
      byte[] signatureBytes = signer.sign();
      signatureBytes = Base64.encodeBase64(signatureBytes);
      return new String(signatureBytes, "UTF-8");
    }
    catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    catch (InvalidKeyException e) {
      throw new IllegalStateException(e);
    }
    catch (SignatureException e) {
      throw new IllegalStateException(e);
    }
    catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Verify the signature of the given signature base string. The signature is verified by generating a new request signature octet string, and comparing it
   * to the signature provided by the Consumer, first URL-decoded per Parameter Encoding, then base64-decoded per RFC2045 section 6.8. The signature is
   * generated using the request parameters as provided by the Consumer, and the Consumer Secret and Token Secret as stored by the Service Provider.
   *
   * @param signatureBaseString The signature base string.
   * @param signature           The signature.
   * @throws InvalidSignatureException
   *                                       If the signature is invalid for the specified base string.
   * @throws UnsupportedOperationException If there is no public key.
   */
  public void verify(String signatureBaseString, String signature) throws InvalidSignatureException {
    if (publicKey == null) {
      throw new UnsupportedOperationException("A public key must be provided to verify signatures.");
    }

    try {
      byte[] signatureBytes = Base64.decodeBase64(signature.getBytes("UTF-8"));
      Signature verifier = Signature.getInstance("SHA1withRSA");
      verifier.initVerify(publicKey);
      verifier.update(signatureBaseString.getBytes("UTF-8"));
      if (!verifier.verify(signatureBytes)) {
        throw new InvalidSignatureException("Invalid signature for signature method " + getName());
      }
    }
    catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
    catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    catch (InvalidKeyException e) {
      throw new IllegalStateException(e);
    }
    catch (SignatureException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * The private key.
   *
   * @return The private key.
   */
  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  /**
   * The private key.
   *
   * @return The private key.
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }
}
