package org.springframework.security.oauth.examples.tonr.mvc;

import org.springframework.security.oauth.examples.tonr.SparklrService;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.OAuthConsumerProcessingFilter;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;

/**
 * @author Ryan Heaton
 */
public class SparklrPhotoController extends AbstractController {

  private static final Pattern REQUEST_PATTERN = Pattern.compile("/sparklr/photo/([^/]+)$");
  private SparklrService sparklrService;

  protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    OAuthConsumerToken token = null;

    //this list of tokens should be initialized by the OAuth consumer filter.
    List<OAuthConsumerToken> tokens = (List<OAuthConsumerToken>) request.getAttribute(OAuthConsumerProcessingFilter.ACCESS_TOKENS_DEFAULT_ATTRIBUTE);
    if (tokens != null) {
      for (OAuthConsumerToken consumerToken : tokens) {
        if (consumerToken.getResourceId().equals("sparklrPhotos")) {
          //get the access token for the sparklr photos (id "sparklrPhotos").
          token = consumerToken;
          break;
        }
      }
    }

    if (token == null) {
      throw new IllegalArgumentException("Access token for sparklr photos not found.");
    }

    Matcher matcher = REQUEST_PATTERN.matcher(request.getRequestURI());
    if (matcher.find()) {
      String id = matcher.group(1);
      InputStream photo = getSparklrService().loadSparklrPhoto(id, token);
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
