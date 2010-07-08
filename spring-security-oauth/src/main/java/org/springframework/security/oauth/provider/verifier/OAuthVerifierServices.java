package org.springframework.security.oauth.provider.verifier;

/**
 * Service for generating a verifier.
 *
 * @author Ryan Heaton
 */
public interface OAuthVerifierServices {

  /**
   * Create a verifier.
   *
   * @return The verifier.
   */
  String createVerifier();
}
