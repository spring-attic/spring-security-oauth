package org.springframework.security.oauth2.consumer;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.consumer.rememberme.HttpSessionOAuth2RememberMeServices;
import org.springframework.security.oauth2.consumer.rememberme.OAuth2RememberMeServices;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * Security filter for an OAuth2 client.
 *
 * @author Ryan Heaton
 */
public class OAuth2ClientContextFilter implements Filter, InitializingBean, MessageSourceAware {

  protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
  private OAuth2ProfileManager profileManager = new OAuth2ProfileChain();
  private OAuth2RememberMeServices rememberMeServices = new HttpSessionOAuth2RememberMeServices();
  private PortResolver portResolver = new PortResolverImpl();
  private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();
  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(profileManager, "An OAuth2 profile manager must be supplied.");
    Assert.notNull(rememberMeServices, "RememberMeOAuth2TokenServices must be supplied.");
    Assert.notNull(redirectStrategy, "A redirect strategy must be supplied.");
  }

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;
    //first set up the security context.
    OAuth2SecurityContextImpl oauth2Context = new OAuth2SecurityContextImpl();
    oauth2Context.setDetails(request);
    
    Map<String, OAuth2AccessToken> accessTokens = getRememberMeServices().loadRememberedTokens(request, response);
    accessTokens = accessTokens == null ? new HashMap<String, OAuth2AccessToken>() : new HashMap<String, OAuth2AccessToken>(accessTokens);
    oauth2Context.setAccessTokens(Collections.unmodifiableMap(accessTokens));
    if (request.getParameter("error") != null) {
      HashMap<String, String> errorParams = new HashMap<String, String>();
      Enumeration parameterNames = request.getParameterNames();
      while (parameterNames.hasMoreElements()) {
        String param = (String) parameterNames.nextElement();
        errorParams.put(param, request.getParameter(param));
      }
      oauth2Context.setErrorParameters(errorParams);
    }
    oauth2Context.setVerificationCode(request.getParameter("code"));
    oauth2Context.setUserAuthorizationRedirectUri(calculateCurrentUri(request));
    oauth2Context.setPreservedState(getRememberMeServices().loadPreservedState(request.getParameter("state"), request, response));

    OAuth2SecurityContextHolder.setContext(oauth2Context);

    try {
      try {
        chain.doFilter(servletRequest, servletResponse);
      }
      catch (Exception ex) {
        OAuth2ProtectedResourceDetails resourceThatNeedsAuthorization = checkForResourceThatNeedsAuthorization(ex);
        String neededResourceId = resourceThatNeedsAuthorization.getId();
        accessTokens.remove(neededResourceId);

        while (!accessTokens.containsKey(neededResourceId)) {
          OAuth2AccessToken accessToken;
          try {
            accessToken = getProfileManager().obtainAccessToken(resourceThatNeedsAuthorization);
            if (accessToken == null) {
              throw new IllegalStateException("Profile manager returned a null access token, which is illegal according to the contract.");
            }
          }
          catch (UserRedirectRequiredException e) {
            redirectUser(e, request, response);
            return;
          }

          accessTokens.put(neededResourceId, accessToken);

          try {
            //try again
            if (!response.isCommitted()) {
              chain.doFilter(request, response);
            }
            else {
              //dang. what do we do now?
              throw new IllegalStateException("Unable to reprocess filter chain with needed OAuth2 resources because the response is already committed.");
            }
          }
          catch (Exception e1) {
            resourceThatNeedsAuthorization = checkForResourceThatNeedsAuthorization(e1);
            neededResourceId = resourceThatNeedsAuthorization.getId();
            accessTokens.remove(neededResourceId);
          }
        }
      }
    }
    finally {
      OAuth2SecurityContextHolder.setContext(null);
      getRememberMeServices().rememberTokens(accessTokens, request, response);
    }
  }

  /**
   * Redirect the user according to the specified exception.
   *
   * @param e The user redirect exception.
   * @param request The request.
   * @param response The response.
   */
  protected void redirectUser(UserRedirectRequiredException e, HttpServletRequest request, HttpServletResponse response) throws IOException {
    if (e.getStateToPreserve() != null) {
      getRememberMeServices().preserveState(e.getStateKey(), e.getStateToPreserve(), request, response);
    }

    try {
      String redirectUri = e.getRedirectUri();
      StringBuilder builder = new StringBuilder(redirectUri);
      Map<String, String> requestParams = e.getRequestParams();
      char appendChar = redirectUri.indexOf('?') < 0 ? '?' : '&';
      for (Map.Entry<String, String> param : requestParams.entrySet()) {
        builder.append(appendChar).append(param.getKey()).append('=').append(URLEncoder.encode(param.getValue(), "UTF-8"));
        appendChar = '&';
      }

      request.setAttribute("org.springframework.security.oauth2.consumer.UserRedirectRequiredException", e);
      this.redirectStrategy.sendRedirect(request, response, builder.toString());
    }
    catch (UnsupportedEncodingException uee) {
      throw new IllegalStateException(uee);
    }
  }

  /**
   * Check the given exception for the resource that needs authorization. If the exception was not thrown because a resource needed authorization, then rethrow
   * the exception.
   *
   * @param ex The exception.
   * @return The resource that needed authorization (never null).
   */
  protected OAuth2ProtectedResourceDetails checkForResourceThatNeedsAuthorization(Exception ex) throws ServletException, IOException {
    Throwable[] causeChain = getThrowableAnalyzer().determineCauseChain(ex);
    OAuth2AccessTokenRequiredException ase = (OAuth2AccessTokenRequiredException) getThrowableAnalyzer().getFirstThrowableOfType(OAuth2AccessTokenRequiredException.class, causeChain);
    OAuth2ProtectedResourceDetails resourceThatNeedsAuthorization;
    if (ase != null) {
      resourceThatNeedsAuthorization = ase.getResource();
      if (resourceThatNeedsAuthorization == null) {
        throw new OAuth2AccessDeniedException(ase.getMessage());
      }
    }
    else {
      // Rethrow ServletExceptions and RuntimeExceptions as-is
      if (ex instanceof ServletException) {
        throw (ServletException) ex;
      }
      if (ex instanceof IOException) {
        throw (IOException) ex;
      }
      else if (ex instanceof RuntimeException) {
        throw (RuntimeException) ex;
      }

      // Wrap other Exceptions. These are not expected to happen
      throw new RuntimeException(ex);
    }
    return resourceThatNeedsAuthorization;
  }

  /**
   * Calculate the current URI given the request.
   *
   * @param request The request.
   * @return The current uri.
   */
  protected String calculateCurrentUri(HttpServletRequest request) throws UnsupportedEncodingException {
    StringBuilder queryBuilder = new StringBuilder();
    Enumeration paramNames = request.getParameterNames();
    while (paramNames.hasMoreElements()) {
      String name = (String) paramNames.nextElement();
      if (!"code".equals(name)) {
        String[] parameterValues = request.getParameterValues(name);
        if (parameterValues.length == 0) {
          queryBuilder.append(URLEncoder.encode(name, "UTF-8"));
        }
        else {
          for (int i = 0; i < parameterValues.length; i++) {
            String parameterValue = parameterValues[i];
            queryBuilder.append(URLEncoder.encode(name, "UTF-8")).append('=').append(URLEncoder.encode(parameterValue, "UTF-8"));
            if (i + 1 < parameterValues.length) {
              queryBuilder.append('&');
            }
          }
        }
      }

      if (paramNames.hasMoreElements()) {
        queryBuilder.append('&');
      }
    }
    
    return UrlUtils.buildFullRequestUrl(request.getScheme(), request.getServerName(), getPortResolver().getServerPort(request), request.getRequestURI(), queryBuilder.length() > 0 ? queryBuilder.toString() : null);
  }

  public void init(FilterConfig filterConfig) throws ServletException {
  }

  public void destroy() {
  }

  /**
   * Set the message source.
   *
   * @param messageSource The message source.
   */
  public void setMessageSource(MessageSource messageSource) {
    this.messages = new MessageSourceAccessor(messageSource);
  }

  public OAuth2ProfileManager getProfileManager() {
    return profileManager;
  }

  public void setProfileManager(OAuth2ProfileManager profileManager) {
    this.profileManager = profileManager;
  }

  public OAuth2RememberMeServices getRememberMeServices() {
    return rememberMeServices;
  }

  public void setRememberMeServices(OAuth2RememberMeServices rememberMeServices) {
    this.rememberMeServices = rememberMeServices;
  }

  public ThrowableAnalyzer getThrowableAnalyzer() {
    return throwableAnalyzer;
  }

  public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
    this.throwableAnalyzer = throwableAnalyzer;
  }

  public PortResolver getPortResolver() {
    return portResolver;
  }

  public void setPortResolver(PortResolver portResolver) {
    this.portResolver = portResolver;
  }

  public RedirectStrategy getRedirectStrategy() {
    return redirectStrategy;
  }

  public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
    this.redirectStrategy = redirectStrategy;
  }
}
