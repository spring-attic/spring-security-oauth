package org.springframework.security.oauth.examples.tonr;

import java.util.List;

/**
 * @author Ryan Heaton
 */
public interface GoogleService {
  List<String> getLastTenPicasaPictureURLs();
}
