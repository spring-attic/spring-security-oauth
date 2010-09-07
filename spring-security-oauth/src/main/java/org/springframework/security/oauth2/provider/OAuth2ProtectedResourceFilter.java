package org.springframework.security.oauth2.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.StringSplitUtils;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.oauth2.common.exceptions.InvalidSignatureException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.token.OAuth2ProviderTokenServices;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Ryan Heaton
 */
public class OAuth2ProtectedResourceFilter extends GenericFilterBean {

  private OAuth2ProviderTokenServices tokenServices;
  private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

  @Override
  public void afterPropertiesSet() throws ServletException {
    super.afterPropertiesSet();
    Assert.notNull(getTokenServices(), "OAuth 2 token services must be supplied.");
  }

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    try {
      Map<String, String> oauthParameters = parseOAuthParameters(request);
      if (oauthParameters != null) {
        if (oauthParameters.containsKey("algorithm")) {
          //todo: support for signature algorithms...
          response.setStatus(401);
          throw new InvalidSignatureException("Unsupported signature: " + oauthParameters.get("algorithm"));
        }

        String token = oauthParameters.get("token");
        OAuth2Authentication auth = null;
        if (token != null) {
          auth = getTokenServices().loadAuthentication(token);
        }

        if (auth == null) {
          response.setStatus(401);
          throw new InvalidTokenException("Invalid token: " + token);
        }

        SecurityContextHolder.getContext().setAuthentication(auth);
      }

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
        String error = "unauthorized";
        if (ase instanceof OAuth2Exception) {
          error = ((OAuth2Exception) ase).getOAuth2ErrorCode();
        }
        setAuthenticateHeader(response, error);
        throw ase;
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

  protected void setAuthenticateHeader(HttpServletResponse response, String error) throws IOException {
    //if a security exception is thrown during an access attempt for a protected resource, we add throw WWW-Authenticate header.
    StringBuilder builder = new StringBuilder("Token ");

    //todo: realm
    //todo: user-uri
    //todo: token-uri

    String algorithms = "";//todo supported algorithms
    builder.append("algorithms=\"").append(algorithms).append("\",");

    //todo: scope

    builder.append("error=\"").append(error).append("\"");

    response.addHeader("WWW-Authenticate", builder.toString());
  }

  protected Map<String, String> parseOAuthParameters(HttpServletRequest request) {
    //first check the header...
    Map<String, String> oauthParameters = parseHeaderParameters(request);

    if (oauthParameters == null) {
      String token = request.getParameter("oauth_token");
      if (token != null) {
        oauthParameters = new HashMap<String, String>(1);
        oauthParameters.put("token", token);

        //(heatonra) the spec currently says that if you're going to do a signature, you have to use the header
        // so we won't parse other request parameters.
      }
    }

    return oauthParameters;
  }

  /**
   * Parse the OAuth header parameters. The parameters will be oauth-decoded.
   *
   * @param request The request.
   * @return The parsed parameters, or null if no OAuth authorization header was supplied.
   */
  protected Map<String, String> parseHeaderParameters(HttpServletRequest request) {
    String header = null;
    Enumeration<String> headers = request.getHeaders("Authorization");
    while (headers.hasMoreElements()) {
      String value = headers.nextElement();
      if ((value.toLowerCase().startsWith("token "))) {
        header = value;
        break;
      }
    }

    Map<String, String> parameters = null;
    if (header != null) {
      parameters = new HashMap<String, String>();
      String authHeaderValue = header.substring(6);

      //create a map of the authorization header values per OAuth Core 1.0, section 5.4.1
      String[] headerEntries = StringSplitUtils.splitIgnoringQuotes(authHeaderValue, ',');
      for (Object o : StringSplitUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"").entrySet()) {
        Map.Entry entry = (Map.Entry) o;
        parameters.put((String) entry.getKey(), (String) entry.getValue());
      }
    }

    return parameters;
  }

  public ThrowableAnalyzer getThrowableAnalyzer() {
    return throwableAnalyzer;
  }

  @Autowired ( required = false )
  public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
    this.throwableAnalyzer = throwableAnalyzer;
  }

  public OAuth2ProviderTokenServices getTokenServices() {
    return tokenServices;
  }

  @Autowired
  public void setTokenServices(OAuth2ProviderTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }

}
