package org.springframework.security.oauth2.provider.webserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.provider.DefaultRedirectStrategy;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedOAuthFlowTypeException;
import org.springframework.security.oauth2.provider.UserDeniedAuthenticationException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * Filter for setting up an end-user endpoint. The filter validates the client authentication request as much as possible and stores the
 * request for later use.
 *
 * @author Ryan Heaton
 */
public class WebServerOAuth2Filter extends AbstractAuthenticationProcessingFilter {

  public static final String DEFAULT_PROCESSING_URL = "/oauth/user/authorize";
  public static final String SAVED_CLIENT_AUTH_REQUEST = "org.springframework.security.oauth2.provider.webserver.WebServerOAuth2Filter#SAVED_CLIENT_AUTH_REQUEST";

  private ClientDetailsService clientDetailsService;
  private VerificationCodeServices verificationServices;
  private ClientAuthenticationCache authenticationCache = new DefaultClientAuthenticationCache();
  private RedirectResolver redirectResolver = new DefaultRedirectResolver();
  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
  private boolean customFailureHandling = false;
  private UserApprovalHandler userApprovalHandler;
  private AuthenticationFailureHandler unapprovedAuthenticationHandler;

  public WebServerOAuth2Filter() {
    super(DEFAULT_PROCESSING_URL);

    setAuthenticationManager(new ProviderManager()); //just set because initialization requires it.
  }

  @Override
  public void afterPropertiesSet() {
    super.afterPropertiesSet();
    Assert.notNull(clientDetailsService, "A client details service must be supplied.");
    Assert.notNull(verificationServices, "Verification code services must be supplied.");
    Assert.notNull(redirectResolver, "A redirect resolver must be supplied.");
    Assert.notNull(authenticationCache, "An authentication cache must be supplied.");
    Assert.notNull(redirectStrategy, "A redirect strategy must be supplied.");
    Assert.notNull(userApprovalHandler, "A user approval handler must be supplied.");
  }

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    String flow = request.getParameter("type");
    if (WebServerOAuth2AuthenticationToken.handlesType(flow)) {
      String clientId = request.getParameter("client_id");
      if (clientId != null) {
        String code = request.getParameter("code");
        if (code == null) {
          //we'll take this as a client authorization request because the code is null, meaning this isn't an access token request.
          ClientDetails clientDetails = getClientDetailsService().loadClientByClientId(clientId);
          List<String> authorizedFlows = clientDetails.getAuthorizedFlows();
          if (authorizedFlows != null && !authorizedFlows.contains(WebServerOAuth2AuthenticationToken.FLOW_TYPE)) {
            throw new UnsupportedOAuthFlowTypeException("Unsupported OAuth flow: " + WebServerOAuth2AuthenticationToken.FLOW_TYPE + ".");
          }

          ClientAuthenticationToken clientAuth = new ClientAuthenticationToken(request, WebServerOAuth2AuthenticationToken.FLOW_TYPE);
          getAuthenticationCache().saveAuthentication(clientAuth, request, response);
          request.setAttribute(SAVED_CLIENT_AUTH_REQUEST, clientAuth);
        }
      }
    }


    super.doFilter(request, response, filterChain);
  }

  @Override
  protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
    ClientAuthenticationToken saved = (ClientAuthenticationToken) request.getAttribute(SAVED_CLIENT_AUTH_REQUEST);

    if (saved != null && saved.isRequiresImmediateAuthentication()) {
      //we require authentication now if the request is immediate
      return true;
    }

    return super.requiresAuthentication(request, response);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!authentication.isAuthenticated()) {
      throw new InsufficientAuthenticationException("User must be authenticated before authorizing an access token.");
    }

    ClientAuthenticationToken saved = getAuthenticationCache().getAuthentication(request, response);
    if (saved == null) {
      throw new InsufficientAuthenticationException("No client authentication request has been issued.");
    }

    if (saved.isDenied()) {
      UserDeniedAuthenticationException udae = new UserDeniedAuthenticationException("User denied authentication.");
      udae.setClientAuthentication(saved);
      throw udae;
    }
    else if (!getUserApprovalHandler().isApproved(saved)) {
      throw new UnapprovedClientAuthenticationException("The client authentication hasn't been approved by the current user.");
    }

    try {
      String clientId = saved.getClientId();
      if (clientId == null) {
        throw new UserDeniedAuthenticationException("Invalid authentication request (no client id).");
      }

      ClientDetails client = getClientDetailsService().loadClientByClientId(clientId);
      String requestedRedirect = saved.getRequestedRedirect();
      String redirectUri = getRedirectResolver().resolveRedirect(requestedRedirect, client);
      if (redirectUri == null) {
        throw new UserDeniedAuthenticationException("A redirect_uri must be supplied.");
      }

      //client authentication request has been approved and validated; remove it from the cache.
      getAuthenticationCache().removeAuthentication(request, response);

      OAuth2Authentication combinedAuth = new OAuth2Authentication(saved, authentication);
      String code = getVerificationServices().createVerificationCode(combinedAuth);
      combinedAuth.setVerificationCode(code);
      combinedAuth.setRedirect(redirectUri);
      return combinedAuth;
    }
    catch (UserDeniedAuthenticationException e) {
      e.setClientAuthentication(saved);
      throw e;
    }
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException, ServletException {
    OAuth2Authentication authentication = (OAuth2Authentication) authResult;
    String redirectUri = authentication.getRedirect();

    ClientAuthenticationToken clientAuth = (ClientAuthenticationToken) authentication.getClientAuthentication();
    String state = clientAuth.getState();
    String verificationCode = authentication.getVerificationCode();

    StringBuilder url = new StringBuilder(redirectUri);
    if (redirectUri.indexOf('?') < 0) {
      url.append('?');
    }
    else {
      url.append('&');
    }
    url.append("code=").append(verificationCode);

    if (state != null) {
      url.append("&state=").append(state);
    }

    getRedirectStrategy().sendRedirect(request, response, url.toString());
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
    if (this.customFailureHandling) {
      super.unsuccessfulAuthentication(request, response, failed);
    }
    else if (failed instanceof UnapprovedClientAuthenticationException) {
      if (this.unapprovedAuthenticationHandler != null) {
        this.unapprovedAuthenticationHandler.onAuthenticationFailure(request, response, failed);
      }
      else {
        throw new AccessDeniedException("User failed to approve client authentication.");
      }
    }
    else if (failed instanceof UserDeniedAuthenticationException) {
      UserDeniedAuthenticationException denial = (UserDeniedAuthenticationException) failed;
      if (denial.getClientAuthentication() == null || denial.getClientAuthentication().getRequestedRedirect() == null) {
        //we have no redirect for the user. very sad.
        throw failed;
      }

      String redirectUri = denial.getClientAuthentication().getRequestedRedirect();
      StringBuilder url = new StringBuilder(redirectUri);
      if (redirectUri.indexOf('?') < 0) {
        url.append('?');
      }
      else {
        url.append('&');
      }
      url.append("error=").append(denial.getOAuth2ErrorCode());

      if (denial.getClientAuthentication().getState() != null) {
        url.append("&state=").append(denial.getClientAuthentication().getState());
      }

      getRedirectStrategy().sendRedirect(request, response, url.toString());
    }
    else {
      // if there's not client authentication request, we'll let the authentication exception up the chain
      // to be handled according to the spring security configuration.
      throw failed;
    }
  }

  public ClientDetailsService getClientDetailsService() {
    return clientDetailsService;
  }

  @Autowired
  public void setClientDetailsService(ClientDetailsService clientDetailsService) {
    this.clientDetailsService = clientDetailsService;
  }

  public VerificationCodeServices getVerificationServices() {
    return verificationServices;
  }

  @Autowired
  public void setVerificationServices(VerificationCodeServices verificationServices) {
    this.verificationServices = verificationServices;
  }

  public RedirectResolver getRedirectResolver() {
    return redirectResolver;
  }

  public void setRedirectResolver(RedirectResolver redirectResolver) {
    this.redirectResolver = redirectResolver;
  }

  public ClientAuthenticationCache getAuthenticationCache() {
    return authenticationCache;
  }

  public void setAuthenticationCache(ClientAuthenticationCache authenticationCache) {
    this.authenticationCache = authenticationCache;
  }

  public RedirectStrategy getRedirectStrategy() {
    return redirectStrategy;
  }

  public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
    this.redirectStrategy = redirectStrategy;
  }

  @Override
  public void setAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
    super.setAuthenticationFailureHandler(failureHandler);
    this.customFailureHandling = true;
  }

  public UserApprovalHandler getUserApprovalHandler() {
    return userApprovalHandler;
  }

  public void setUserApprovalHandler(UserApprovalHandler userApprovalHandler) {
    this.userApprovalHandler = userApprovalHandler;
  }

  public AuthenticationFailureHandler getUnapprovedAuthenticationHandler() {
    return unapprovedAuthenticationHandler;
  }

  public void setUnapprovedAuthenticationHandler(AuthenticationFailureHandler unapprovedAuthenticationHandler) {
    this.unapprovedAuthenticationHandler = unapprovedAuthenticationHandler;
  }
}
