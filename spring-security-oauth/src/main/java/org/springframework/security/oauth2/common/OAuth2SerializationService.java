package org.springframework.security.oauth2.common;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * Interface for OAuth 2 (de)serialization services.
 *
 * @author Ryan Heaton
 */
public interface OAuth2SerializationService {

  /**
   * Serialize an access token.
   *
   * @param accessToken The access token to serialize.
   * @param serializationType The serialization type (null to specify default serialization type).
   * @return The serialization.
   */
  OAuth2Serialization serialize(OAuth2AccessToken accessToken, String serializationType);

  /**
   * Deserialize an access token.
   *
   * @param serialization The serialization.
   * @return The access token.
   */
  OAuth2AccessToken deserializeAccessToken(OAuth2Serialization serialization);

  /**
   * Serialize an exception.
   *
   * @param exception The exception to serialize.
   * @param serializationType The serialization type (null to specify default serialization type).
   * @return The serialization.
   */
  OAuth2Serialization serialize(OAuth2Exception exception, String serializationType);

  /**
   * Deserialize an oauth error.
   *
   * @param serialization The serialization.
   * @return The exception.
   */
  OAuth2Exception deserializeError(OAuth2Serialization serialization);
}
