package org.springframework.security.oauth.examples.sparklr;

import java.io.InputStream;
import java.util.Collection;

/**
 * Service for retrieving photos.
 * 
 * @author Ryan Heaton
 */
public interface PhotoService {

  /**
   * Load the photos for the current user.
   *
   * @return The photos for the current user.
   */
  Collection<PhotoInfo> getPhotosForCurrentUser(String username);

  /**
   * Load a photo by id.
   * 
   * @param id The id of the photo.
   * @return The photo that was read.
   */
  InputStream loadPhoto(String id);
}
