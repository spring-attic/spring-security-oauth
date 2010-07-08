package org.springframework.security.oauth.examples.tonr;

import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;

import java.util.List;
import java.io.InputStream;

/**
 * @author Ryan Heaton
 */
public interface SparklrService {

  /**
   * Get the list of Sparklr photo ids for the current user.
   *
   * @param accessToken The OAuth access token to use.
   * @return The list of photo ids for the current user.
   */
  List<String> getSparklrPhotoIds(OAuthConsumerToken accessToken) throws SparklrException;

  /**
   * Loads the Sparklr photo for the current user.
   *
   * @param id the id or the photo.
   * @param accessToken The OAuth access token to use.
   * @return The sparklr photo.
   */
  InputStream loadSparklrPhoto(String id, OAuthConsumerToken accessToken) throws SparklrException;
}
