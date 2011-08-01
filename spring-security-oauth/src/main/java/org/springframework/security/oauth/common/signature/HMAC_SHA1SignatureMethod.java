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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * HMAC-SHA1 signature method.
 *
 * @author Ryan Heaton
 */
public class HMAC_SHA1SignatureMethod implements OAuthSignatureMethod {

  private static final Log LOG = LogFactory.getLog(HMAC_SHA1SignatureMethod.class);

  /**
   * The name of this HMAC-SHA1 signature method ("HMAC-SHA1").
   */
  public static final String SIGNATURE_NAME = "HMAC-SHA1";

  /**
   * The MAC name (for interfacing with javax.crypto.*).  "HmacSHA1".
   */
  public static final String MAC_NAME = "HmacSHA1";

  private final SecretKey key;

  /**
   * Construct a HMAC-SHA1 signature method with the given HMAC-SHA1 key.
   *
   * @param key The key.
   */
  public HMAC_SHA1SignatureMethod(SecretKey key) {
    this.key = key;
  }

  /**
   * The name of this HMAC-SHA1 signature method ("HMAC-SHA1").
   *
   * @return The name of this HMAC-SHA1 signature method.
   */
  public String getName() {
    return SIGNATURE_NAME;
  }

  /**
   * Sign the signature base string. The signature is the digest octet string, first base64-encoded per RFC2045, section 6.8, then URL-encoded per
   * OAuth Parameter Encoding.
   *
   * @param signatureBaseString The signature base string.
   * @return The signature.
   */
  public String sign(String signatureBaseString) {
    try {
      Mac mac = Mac.getInstance(MAC_NAME);
      mac.init(key);
      byte[] text = signatureBaseString.getBytes("UTF-8");
      byte[] signatureBytes = mac.doFinal(text);
      signatureBytes = Base64.encodeBase64(signatureBytes);
      String signature = new String(signatureBytes, "UTF-8");

      if (LOG.isDebugEnabled()) {
        LOG.debug("signature base: " + signatureBaseString);
        LOG.debug("signature: " + signature);
      }

      return signature;
    }
    catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    catch (InvalidKeyException e) {
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
   * @throws InvalidSignatureException If the signature is invalid for the specified base string.
   */
  public void verify(String signatureBaseString, String signature) throws InvalidSignatureException {
    try {
      if (LOG.isDebugEnabled()) {
        LOG.debug("signature base: " + signatureBaseString);
        LOG.debug("signature: " + signature);
      }

      byte[] signatureBytes = Base64.decodeBase64(signature.getBytes("UTF-8"));

      Mac mac = Mac.getInstance(MAC_NAME);
      mac.init(key);
      byte[] text = signatureBaseString.getBytes("UTF-8");
      byte[] calculatedBytes = mac.doFinal(text);
      if (!safeArrayEquals(calculatedBytes, signatureBytes)) {
        throw new InvalidSignatureException("Invalid signature for signature method " + getName());
      }
    }
    catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    catch (InvalidKeyException e) {
      throw new IllegalStateException(e);
    }
    catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  boolean safeArrayEquals(byte[] a1, byte[] a2) {
    if (a1 == null || a2 == null) {
      return (a1 == a2);
    }

    if (a1.length != a2.length) {
      return false;
    }

    byte result = 0;
    for (int i = 0; i < a1.length; i++) {
      result |= a1[i] ^ a2[i];
    }
    
    return (result == 0);
  }

  /**
   * The secret key.
   *
   * @return The secret key.
   */
  public SecretKey getSecretKey() {
    return key;
  }
}