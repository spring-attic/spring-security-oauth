package org.springframework.security.oauth.examples.tonr.mvc;

import org.springframework.security.oauth.examples.tonr.SparklrService;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Ryan Heaton
 */
public class SparklrPhotoController extends AbstractController {

  private static final Pattern REQUEST_PATTERN = Pattern.compile("/sparklr/photo/([^/]+)$");
  private SparklrService sparklrService;

  protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    Matcher matcher = REQUEST_PATTERN.matcher(request.getRequestURI());
    if (matcher.find()) {
      String id = matcher.group(1);
      InputStream photo = getSparklrService().loadSparklrPhoto(id);
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

  public SparklrService getSparklrService() {
    return sparklrService;
  }

  public void setSparklrService(SparklrService sparklrService) {
    this.sparklrService = sparklrService;
  }
}
