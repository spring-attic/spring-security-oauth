package org.springframework.security.oauth2.provider.webserver;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter used to handle the approval of a user for a client authentication request.
 *
 * @author Ryan Heaton
 */
public class BasicUserApprovalFilter extends GenericFilterBean implements UserApprovalHandler {

  public static final String DEFAULT_APPROVAL_REQUEST_PARAMETER = "user_oauth_approval";
  public static final String DEFAULT_APPROVAL_PARAMETER_VALUE = "true";

  private ClientAuthenticationCache authenticationCache = new DefaultClientAuthenticationCache();
  private String approvalParameter = DEFAULT_APPROVAL_REQUEST_PARAMETER;
  private String approvalParameterValue = DEFAULT_APPROVAL_PARAMETER_VALUE;

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    if (requiresProcessing(request)) {
      ClientAuthenticationToken authToken = getAuthenticationCache().getAuthentication((HttpServletRequest) request, (HttpServletResponse) response);
      if (authToken == null) {
        throw createIllegalApprovalRequestException();
      }
      else {
        authToken.setDenied(!isApproval(request));
        getAuthenticationCache().updateAuthentication(authToken, (HttpServletRequest) request, (HttpServletResponse) response);
      }
    }

    chain.doFilter(request, response);
  }

  /**
   * Basic implementation just requires the client authentication to be authenticated.
   *
   * @param clientAuthentication The client authentication.
   * @return Whether the specified client authentication has been approved by the current user.
   */
  public boolean isApproved(ClientAuthenticationToken clientAuthentication) {
    return clientAuthentication.isAuthenticated();
  }

  protected boolean requiresProcessing(ServletRequest request) {
    return request.getParameterMap().containsKey(getApprovalParameter());
  }

  protected boolean isApproval(ServletRequest request) {
    return getApprovalParameterValue().equals(request.getParameter(getApprovalParameter()));
  }

  protected RuntimeException createIllegalApprovalRequestException() {
    return new AuthenticationServiceException(String.format("Request parameter %s may only be applied in the middle of an oauth web server approval flow.", DEFAULT_APPROVAL_REQUEST_PARAMETER));
  }

  public ClientAuthenticationCache getAuthenticationCache() {
    return authenticationCache;
  }

  public void setAuthenticationCache(ClientAuthenticationCache authenticationCache) {
    this.authenticationCache = authenticationCache;
  }

  public String getApprovalParameter() {
    return approvalParameter;
  }

  public void setApprovalParameter(String approvalParameter) {
    this.approvalParameter = approvalParameter;
  }

  public String getApprovalParameterValue() {
    return approvalParameterValue;
  }

  public void setApprovalParameterValue(String approvalParameterValue) {
    this.approvalParameterValue = approvalParameterValue;
  }
}
