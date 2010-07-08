package org.springframework.security.oauth.examples.sparklr.mvc;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Controller for the home page.
 *
 * @author Ryan Heaton
 */
public class HomeController extends AbstractController {

  protected ModelAndView handleRequestInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Exception {
    return new ModelAndView("home");
  }

}
