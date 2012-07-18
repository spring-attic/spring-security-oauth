/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth.examples.sparklr.impl;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth.examples.sparklr.PhotoInfo;
import org.springframework.security.oauth.examples.sparklr.PhotoService;
import org.springframework.security.authentication.BadCredentialsException;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Basic implementation for the photo service.
 *
 * @author Ryan Heaton
 */
public class PhotoServiceImpl implements PhotoService {

  private List<PhotoInfo> photos;

  public Collection<PhotoInfo> getPhotosForCurrentUser() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication.getPrincipal() instanceof UserDetails) {
      UserDetails details = (UserDetails) authentication.getPrincipal();
      String username = details.getUsername();
      ArrayList<PhotoInfo> infos = new ArrayList<PhotoInfo>();
      for (PhotoInfo info : getPhotos()) {
        if (username.equals(info.getUserId())) {
          infos.add(info);
        }
      }
      return infos;
    }
    else {
      throw new BadCredentialsException("Bad credentials: not a username/password authentication.");
    }
  }

  public InputStream loadPhoto(String id) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication.getPrincipal() instanceof UserDetails) {
      UserDetails details = (UserDetails) authentication.getPrincipal();
      String username = details.getUsername();
      for (PhotoInfo photoInfo : getPhotos()) {
        if (id.equals(photoInfo.getId()) && username.equals(photoInfo.getUserId())) {
          URL resourceURL = getClass().getResource(photoInfo.getResourceURL());
          if (resourceURL != null) {
            try {
              return resourceURL.openStream();
            }
            catch (IOException e) {
              //fall through...
            }
          }
        }
      }
    }
    return null;
  }

  public List<PhotoInfo> getPhotos() {
    return photos;
  }

  public void setPhotos(List<PhotoInfo> photos) {
    this.photos = photos;
  }
}
