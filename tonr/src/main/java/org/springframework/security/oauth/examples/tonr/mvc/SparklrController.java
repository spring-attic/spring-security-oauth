package org.springframework.security.oauth.examples.tonr.mvc;

import org.springframework.security.oauth.consumer.OAuthConsumerProcessingFilter;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.security.oauth.examples.tonr.SparklrService;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * @author Ryan Heaton
 */
public class SparklrController extends AbstractController {

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

    List<String> photoIds = getSparklrService().getSparklrPhotoIds(token);
    return new ModelAndView("sparklr", "photoIds", photoIds);
  }

  public SparklrService getSparklrService() {
    return sparklrService;
  }

  public void setSparklrService(SparklrService sparklrService) {
    this.sparklrService = sparklrService;
  }
}
