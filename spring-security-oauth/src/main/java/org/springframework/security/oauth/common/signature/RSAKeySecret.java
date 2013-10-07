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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.UnsupportedEncodingException;

/**
 * Signature secret for RSA.
 *
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class RSAKeySecret implements SignatureSecret {

  private final PrivateKey privateKey;
  private final PublicKey publicKey;

  public RSAKeySecret(PrivateKey privateKey, PublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Create an RSA public key secret with the given private and public key value. The value of the private key is
   * assumed to be the PKCS#8-encoded bytes of the private key. The value of the public key is assumed to be
   * the X509-encoded bytes of the public key.
   *
   * @param privateKey The value of the private key.
   * @param publicKey The value of the public key.
   */
  public RSAKeySecret(byte[] privateKey, byte[] publicKey) {
    this(createPrivateKey(privateKey), createPublicKey(publicKey));
  }

  /**
   * Create an RSA public key secret with the given private and public key.  The values are assumed to be
   * the Base64-encoded values of the bytes of the keys, X509-encoded for the public key and PKCS#8-encoded
   * for the private key.
   *
   * @param privateKey The value of the private key.
   * @param publicKey The value of the public key.
   */
  public RSAKeySecret(String privateKey, String publicKey) {
    this(base64Decode(privateKey), base64Decode(publicKey));
  }

  /**
   * Construct an RSA public key secret with the given public key. The private key will be null.
   *
   * @param publicKey The public key.
   */
  public RSAKeySecret(PublicKey publicKey) {
    this(null, publicKey);
  }

  /**
   * Create an RSA public key secret with the given public key value.  The value is assumed to be
   * the X509-encoded bytes of the public key. The private key will be null.
   *
   * @param publicKey The value of the public key.
   */
  public RSAKeySecret(byte[] publicKey) {
    this(null, createPublicKey(publicKey));
  }

  /**
   * Create an RSA public key secret with the given public key value.  The value is assumed to be
   * the Base64-encoded value of the X509-encoded bytes of the public key. The private key will be null.
   *
   * @param publicKey The value of the public key.
   */
  public RSAKeySecret(String publicKey) {
    this(base64Decode(publicKey));
  }

  /**
   * Create an RSA public key secret with the given X509 certificate. The private key will be null.
   *
   * @param certificate The certificate.
   */
  public RSAKeySecret(X509Certificate certificate) {
    this(certificate.getPublicKey());
  }

  /**
   * Creates a public key from the X509-encoded value of the given bytes.
   *
   * @param publicKey The X509-encoded public key bytes.
   * @return The public key.
   */
  public static PublicKey createPublicKey(byte[] publicKey) {
    if (publicKey == null) {
      return null;
    }
    
    try {
      KeyFactory fac = KeyFactory.getInstance("RSA");
      EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
      return fac.generatePublic(spec);
    }
    catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    catch (InvalidKeySpecException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Creates a private key from the PKCS#8-encoded value of the given bytes.
   *
   * @param privateKey The PKCS#8-encoded private key bytes.
   * @return The private key.
   */
  public static PrivateKey createPrivateKey(byte[] privateKey) {
    if (privateKey == null) {
      return null;
    }

    try {
      KeyFactory fac = KeyFactory.getInstance("RSA");
      EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey);
      return fac.generatePrivate(spec);
    }
    catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    catch (InvalidKeySpecException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Utility method for decoding a base-64-encoded string.
   *
   * @param value The base-64-encoded string.
   * @return The decoded value.
   */
  private static byte[] base64Decode(String value) {
    if (value == null) {
      return null;
    }
    
    try {
      return Base64.decodeBase64(value.getBytes("UTF-8"));
    }
    catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
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
   * The public key.
   *
   * @return The public key.
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }
}
