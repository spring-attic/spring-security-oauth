package org.springframework.security.oauth2.provider.response;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.web.servlet.ModelAndView;

import java.util.Set;

/**
 * Interface for handling OAuth2 response types (e.g. code and token and possible others). This interface provides for
 * a hook for custom implementations build on top of the OAuth2 framework.
 *
 * @author Okke Harsta
 *
 */
public interface ResponseTypesHandler {

    /**
     * Fail-fast method for finding out if the set of responses can be handled by this ResponseTypesHandler
     *
     * @param responseTypes the response types of an authorize request
     * @return true if the set of response types can be handles
     */
    boolean canHandleResponseTypes(Set<String> responseTypes);

    /**
     * Handle the authorization request for the given responseTypes
     *
     * @param responseTypes the reponse types requested by the authorization
     * @param authorizationRequest the approved AuthorizationRequest
     * @param authentication the authenticated user
     * @param authorizationCodeServices responsible for creating the authorization code
     * @return a ModelAndView for either redirect, JSON response or any other custom handling
     */
    ModelAndView handleApprovedAuthorizationRequest(Set<String> responseTypes,
                                                    AuthorizationRequest authorizationRequest,
                                                    Authentication authentication,
                                                    AuthorizationCodeServices authorizationCodeServices);
}
