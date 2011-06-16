package org.springframework.security.oauth.examples.sparklr.mvc;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

/**
 * Controller for a resource that is specific to a trusted client.
 *
 * @author Ryan Heaton
 */
public class TrustedClientController extends AbstractController {

  @PreAuthorize("oauthClientHasRole('ROLE_TRUSTED_CLIENT')")
  @Override
  public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
    return super.handleRequest(request, response);
  }

  protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    response.setStatus(200);
    response.setContentType("text/plain");
    PrintWriter writer = response.getWriter();
    writer.write("Hello, Trusted Client");
    writer.flush();
    writer.close();
    
    return null;
  }
}
