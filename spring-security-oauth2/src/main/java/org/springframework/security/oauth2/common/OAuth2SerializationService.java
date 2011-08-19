package org.springframework.security.oauth2.common;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.SerializationException;

import java.io.InputStream;
import java.util.Map;

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
   * @return The serialization (json format, per the spec).
   */
  String serialize(OAuth2AccessToken accessToken);

  /**
   * Deserialize an access token from standard JSON format.
   *
   * @param serialization The JSON.
   * @return The access token.
   */
  OAuth2AccessToken deserializeJsonAccessToken(InputStream serialization);

  /**
   * Deserialize an access token.
   *
   * @param tokenParams The parsed token parameters.
   * @return The access token.
   */
  OAuth2AccessToken deserializeAccessToken(Map<String, String> tokenParams);

  /**
   * Serialize an exception.
   *
   * @param exception The exception to serialize.
   * @return The serialization (json format, per the spec).
   */
  String serialize(OAuth2Exception exception);

  /**
   * Deserialize an JSON oauth error.
   *
   * @param serialization The serialization (json format, per the spec).
   * @return The exception.
   * @throws SerializationException If the JSON deserialization failed.
   */
  OAuth2Exception deserializeJsonError(InputStream serialization) throws SerializationException;

  /**
   * Deserialize an oauth error.
   *
   * @param errorParams The error parameters.
   * @return The exception.
   */
  OAuth2Exception deserializeError(Map<String, String> errorParams);

}
