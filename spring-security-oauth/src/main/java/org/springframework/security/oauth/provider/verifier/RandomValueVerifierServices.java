package org.springframework.security.oauth.provider.verifier;

import org.springframework.beans.factory.InitializingBean;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Basic implementation of the verifier services that creates a random-value verifier and stores it in an in-memory map.
 *
 * @author Ryan Heaton
 */
public class RandomValueVerifierServices implements OAuthVerifierServices, InitializingBean {

  private static final char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();

  private Random random;
  private int verifierLengthBytes = 6;

  public void afterPropertiesSet() throws Exception {
    if (getRandom() == null) {
      setRandom(new SecureRandom());
    }
  }

  public String createVerifier() {
    byte[] verifierBytes = new byte[getVerifierLengthBytes()];
    getRandom().nextBytes(verifierBytes);
    return getVerifierString(verifierBytes);
  }

  /**
   * Convert these random bytes to a verifier string. The length of the byte array can be {@link #setVerifierLengthBytes(int) configured}. Default implementation
   * mods the bytes to fit into the ASCII letters 1-9, A-Z, a-z .
   * 
   * @param verifierBytes The bytes.
   * @return The string.
   */
  protected String getVerifierString(byte[] verifierBytes) {
    char[] chars = new char[verifierBytes.length];
    for (int i = 0; i < verifierBytes.length; i++) {
      chars[i] = DEFAULT_CODEC[((verifierBytes[i] & 0xFF) % DEFAULT_CODEC.length)];
    }
    return new String(chars);
  }

  /**
   * The random value generator used to create token secrets.
   *
   * @return The random value generator used to create token secrets.
   */
  public Random getRandom() {
    return random;
  }

  /**
   * The random value generator used to create token secrets.
   *
   * @param random The random value generator used to create token secrets.
   */
  public void setRandom(Random random) {
    this.random = random;
  }

  /**
   * The verifier length in bytes, before being encoded to a string.
   *
   * @return The verifier length in bytes, before being encoded to a string.
   */
  public int getVerifierLengthBytes() {
    return verifierLengthBytes;
  }

  /**
   * The verifier length in bytes, before being encoded to a string.
   *
   * @param verifierLengthBytes The verifier length in bytes, before being encoded to a string.
   */
  public void setVerifierLengthBytes(int verifierLengthBytes) {
    this.verifierLengthBytes = verifierLengthBytes;
  }
}