package org.springframework.security.oauth.examples.sparklr.mvc;

import org.springframework.security.oauth.examples.sparklr.PhotoService;
import org.springframework.web.servlet.mvc.AbstractController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletOutputStream;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.InputStream;

/**
 * Controller for a specific photo.
 *
 * @author Ryan Heaton
 */
public class PhotoController extends AbstractController {

  private static final Pattern REQUEST_PATTERN = Pattern.compile("/photo/([^/]+)$");
  private PhotoService photoService;

  protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    Matcher matcher = REQUEST_PATTERN.matcher(request.getRequestURI());
    if (matcher.find()) {
      String id = matcher.group(1);
      InputStream photo = getPhotoService().loadPhoto(id);
      if (photo == null) {
        response.sendError(404);
      }
      else {
        response.setContentType("image/jpeg");
        ServletOutputStream out = response.getOutputStream();
        byte[] buffer = new byte[1024];
        int len = photo.read(buffer);
        while (len >= 0) {
          out.write(buffer, 0, len);
          len = photo.read(buffer);
        }
      }
    }
    else {
      response.sendError(404);
    }

    return null;
  }

  public PhotoService getPhotoService() {
    return photoService;
  }

  public void setPhotoService(PhotoService photoService) {
    this.photoService = photoService;
  }
}
