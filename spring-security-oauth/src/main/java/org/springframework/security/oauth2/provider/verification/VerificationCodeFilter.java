package org.springframework.security.oauth2.provider.verification;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.*;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
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
import java.util.Map;
import java.util.Set;

/**
 * Filter for setting up an end-user endpoint. The filter validates the client authentication request as much as possible and stores the
 * request for later use.
 *
 * @author Ryan Heaton
 */
public class VerificationCodeFilter extends AbstractAuthenticationProcessingFilter {

  private static final String VERIFICATION_CODE_ATTRIBUTE = VerificationCodeFilter.class.getName() + "#CODE";
  private static final String VERIFICATION_TOKEN_ATTRIBUTE = VerificationCodeFilter.class.getName() + "#TOKEN";

  public static final String DEFAULT_PROCESSING_URL = "/oauth/user/authorize";

  private ClientDetailsService clientDetailsService;
  private VerificationCodeServices verificationServices;
  private ClientAuthenticationCache authenticationCache = new DefaultClientAuthenticationCache();
  private RedirectResolver redirectResolver = new DefaultRedirectResolver();
  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
  private boolean customFailureHandling = false;
  private UserApprovalHandler userApprovalHandler;
  private AuthenticationFailureHandler unapprovedAuthenticationHandler;

  public VerificationCodeFilter() {
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

    String responseType = request.getParameter("response_type");
    if ("code".equals(responseType)) {
      //if the "response_type" is "code", we can process this request.
      String clientId = request.getParameter("client_id");
      String redirectUri = request.getParameter("redirect_uri");
      Set<String> scope = OAuth2Utils.parseScope(request.getParameter("scope"));
      String state = request.getParameter("state");
      VerificationCodeAuthenticationToken verificationAuthenticationToken = new VerificationCodeAuthenticationToken(clientId, scope, state, redirectUri);
      if (clientId == null) {
        request.setAttribute(VERIFICATION_TOKEN_ATTRIBUTE, verificationAuthenticationToken);
        unsuccessfulAuthentication(request, response, new InvalidClientException("A client_id parameter must be supplied."));
        return;
      }
      else {
        getAuthenticationCache().saveAuthentication(verificationAuthenticationToken, request, response);
      }
    }
    else if ("token".equals(responseType)) {
      throw new UnsupportedResponseTypeException("Unsupported response type: token.");
    }
    else if ("code_and_token".equals(responseType)) {
      throw new UnsupportedResponseTypeException("Unsupported response type: code_and_token.");
    }

    super.doFilter(request, response, filterChain);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
      throw new InsufficientAuthenticationException("User must be authenticated before authorizing an access token.");
    }

    VerificationCodeAuthenticationToken saved = getAuthenticationCache().getAuthentication(request, response);
    if (saved == null) {
      throw new InsufficientAuthenticationException("No client authentication request has been issued.");
    }

    request.setAttribute(VERIFICATION_TOKEN_ATTRIBUTE, saved);
    try {
      if (saved.isDenied()) {
        throw new UserDeniedVerificationException("User denied authentication.");
      }
      else if (!getUserApprovalHandler().isApproved(saved)) {
        throw new UnapprovedClientAuthenticationException("The client authentication hasn't been approved by the current user.");
      }

      String clientId = saved.getClientId();
      if (clientId == null) {
        throw new InvalidClientException("Invalid authentication request (no client id).");
      }

      ClientDetails client = getClientDetailsService().loadClientByClientId(clientId);
      String requestedRedirect = saved.getRequestedRedirect();
      String redirectUri = getRedirectResolver().resolveRedirect(requestedRedirect, client);
      if (redirectUri == null) {
        throw new OAuth2Exception("A redirect_uri must be supplied.");
      }

      //client authentication request has been approved and validated; remove it from the cache.
      getAuthenticationCache().removeAuthentication(request, response);

      OAuth2Authentication<VerificationCodeAuthenticationToken, Authentication> combinedAuth
        = new OAuth2Authentication<VerificationCodeAuthenticationToken, Authentication>(saved, authentication);
      String code = getVerificationServices().createVerificationCode(combinedAuth);
      request.setAttribute(VERIFICATION_CODE_ATTRIBUTE, code);
      return combinedAuth;
    }
    catch (OAuth2Exception e) {
      if (saved.getState() != null) {
        e.addAdditionalInformation("state", saved.getState());
      }

      throw e;
    }
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException, ServletException {
    OAuth2Authentication authentication = (OAuth2Authentication) authResult;
    String verificationCode = (String) request.getAttribute(VERIFICATION_CODE_ATTRIBUTE);
    if (verificationCode == null) {
      throw new IllegalStateException("No verification code found in the current request scope.");
    }

    VerificationCodeAuthenticationToken clientAuth = (VerificationCodeAuthenticationToken) authentication.getClientAuthentication();
    String requestedRedirect = clientAuth.getRequestedRedirect();
    String state = clientAuth.getState();

    StringBuilder url = new StringBuilder(requestedRedirect);
    if (requestedRedirect.indexOf('?') < 0) {
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
    else if (failed instanceof OAuth2Exception) {
      OAuth2Exception failure = (OAuth2Exception) failed;
      VerificationCodeAuthenticationToken token = (VerificationCodeAuthenticationToken) request.getAttribute(VERIFICATION_TOKEN_ATTRIBUTE);
      if (token == null || token.getRequestedRedirect() == null) {
        //we have no redirect for the user. very sad.
        throw new UnapprovedClientAuthenticationException("Verification failure, and no redirect URI.", failed);
      }

      String redirectUri = token.getRequestedRedirect();
      StringBuilder url = new StringBuilder(redirectUri);
      if (redirectUri.indexOf('?') < 0) {
        url.append('?');
      }
      else {
        url.append('&');
      }
      url.append("error=").append(failure.getOAuth2ErrorCode());
      url.append("&error_description=").append(failure.getMessage());

      if (failure.getAdditionalInformation() != null) {
        for (Map.Entry<String, String> additionalInfo : failure.getAdditionalInformation().entrySet()) {
          url.append('&').append(additionalInfo.getKey()).append('=').append(additionalInfo.getValue());
        }
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
