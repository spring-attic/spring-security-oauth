package org.springframework.security.oauth.examples.tonr.mvc;

import org.springframework.security.oauth.examples.tonr.GoogleService;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Ryan Heaton
 */
public class PicasaController extends AbstractController {

  private GoogleService googleService;

  @Override
  protected ModelAndView handleRequestInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Exception {
    return new ModelAndView("picasa", "photoUrls", getGoogleService().getLastTenPicasaPictureURLs());
  }
  
  public GoogleService getGoogleService() {
    return googleService;
  }

  public void setGoogleService(GoogleService googleService) {
    this.googleService = googleService;
  }
}
