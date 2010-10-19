package org.springframework.security.oauth.examples.tonr.mvc;

import org.springframework.security.oauth.examples.tonr.SparklrService;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Ryan Heaton
 */
public class SparklrController extends AbstractController {

  private SparklrService sparklrService;

  protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    return new ModelAndView("sparklr", "photoIds", getSparklrService().getSparklrPhotoIds());
  }

  public SparklrService getSparklrService() {
    return sparklrService;
  }

  public void setSparklrService(SparklrService sparklrService) {
    this.sparklrService = sparklrService;
  }
}
