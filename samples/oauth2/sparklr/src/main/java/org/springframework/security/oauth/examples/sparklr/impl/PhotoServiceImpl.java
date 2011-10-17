package org.springframework.security.oauth.examples.sparklr.impl;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth.examples.sparklr.PhotoInfo;
import org.springframework.security.oauth.examples.sparklr.PhotoService;

/**
 * Basic implementation for the photo service.
 * 
 * @author Ryan Heaton
 */
public class PhotoServiceImpl implements PhotoService {

	private List<PhotoInfo> photos;

	public Collection<PhotoInfo> getPhotosForCurrentUser(String username) {

		ArrayList<PhotoInfo> infos = new ArrayList<PhotoInfo>();
		for (PhotoInfo info : getPhotos()) {
			if (username.equals(info.getUserId())) {
				infos.add(info);
			}
		}
		return infos;

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
						} catch (IOException e) {
							// fall through...
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
