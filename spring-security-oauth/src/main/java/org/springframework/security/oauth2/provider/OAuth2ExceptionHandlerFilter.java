package org.springframework.security.oauth2.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter for handling OAuth2-specific exceptions.
 *
 * @author Ryan Heaton
 */
public class OAuth2ExceptionHandlerFilter extends GenericFilterBean {

  private OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
  private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;

    try {
      chain.doFilter(request, response);

      if (logger.isDebugEnabled()) {
        logger.debug("Chain processed normally");
      }
    }
    catch (IOException ex) {
      throw ex;
    }
    catch (Exception ex) {
      // Try to extract a SpringSecurityException from the stacktrace
      Throwable[] causeChain = getThrowableAnalyzer().determineCauseChain(ex);
      RuntimeException ase = (AuthenticationException)
        getThrowableAnalyzer().getFirstThrowableOfType(AuthenticationException.class, causeChain);

      if (ase == null) {
        ase = (AccessDeniedException) getThrowableAnalyzer().getFirstThrowableOfType(AccessDeniedException.class, causeChain);
      }

      if (ase != null) {
        handleSecurityException(request, response, chain, ase);
      }
      else {
        // Rethrow ServletExceptions and RuntimeExceptions as-is
        if (ex instanceof ServletException) {
          throw (ServletException) ex;
        }
        else if (ex instanceof RuntimeException) {
          throw (RuntimeException) ex;
        }

        // Wrap other Exceptions. These are not expected to happen
        throw new RuntimeException(ex);
      }
    }
  }

  protected void handleSecurityException(HttpServletRequest request, HttpServletResponse response, FilterChain chain, RuntimeException ase) throws IOException {
    if (ase instanceof OAuth2Exception) {
      if (logger.isDebugEnabled()) {
        logger.debug("OAuth error.", ase);
      }
      
      String serialization = getSerializationService().serialize((OAuth2Exception) ase);
      response.setStatus(((OAuth2Exception) ase).getHttpErrorCode());
      response.setHeader("Cache-Control", "no-store");
      response.setContentType("application/json");
      response.getWriter().write(serialization);
      response.flushBuffer();
      return;
    }

    //we don't care about anything but oauth exceptions.
    throw ase;
  }

  public ThrowableAnalyzer getThrowableAnalyzer() {
    return throwableAnalyzer;
  }

  @Autowired ( required = false )
  public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
    this.throwableAnalyzer = throwableAnalyzer;
  }

  public OAuth2SerializationService getSerializationService() {
    return serializationService;
  }

  public void setSerializationService(OAuth2SerializationService serializationService) {
    this.serializationService = serializationService;
  }

}
