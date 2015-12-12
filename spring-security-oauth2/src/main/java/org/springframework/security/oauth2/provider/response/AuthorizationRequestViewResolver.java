package org.springframework.security.oauth2.provider.response;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

/**
 * AuthorizationRequestViewResolver is responsible for constructing the Views returned to the requester in response
 * to an AuthorizationRequest for the OAuth2 flows.
 *
 * @author Okke Harsta
 */
public interface AuthorizationRequestViewResolver {

    /**
     * Resolve the resulting View for the AuthorizationCode flow
     *
     * @param authorizationRequest the authorization request from the user
     * @param authorizationCode the code to exchange for a token
     * @return View containing the authorizationCode
     */
    View getSuccessfulAuthorizationCodeView(AuthorizationRequest authorizationRequest,
                                            String authorizationCode);

    /**
     * Resolve the resulting View for the ImplicitGrant flow
     *
     * @param authorizationRequest the authorization request from the user
     * @param accessToken the accessToken to include in the redirect
     * @return View containing the accessToken
     */
    View getSuccessfulImplicitGrantView(AuthorizationRequest authorizationRequest,
                                        OAuth2AccessToken accessToken);
    /**
     * Resolve the resulting View for a unsuccessful authorization request. Note that
     * it must handle both ImplicitGrant and AuthorizationCode requests (e.g. use the fragment or not)
     *
     * @param authorizationRequest the authorization request from the user
     * @param failure reason why it went wrong
     * @return View with the exposed error
     */
    View getUnsuccessfulView(AuthorizationRequest authorizationRequest, OAuth2Exception failure);


}
