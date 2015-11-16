package org.springframework.security.oauth2.provider.response;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.web.servlet.ModelAndView;

import java.util.Set;

/**
 * Interface for handling custom OAuth2 response types (e.g. other then code and token). This provides for a hook
 * for custom implementations build on top of the OAuth2 framework.
 *
 * @author Okke Harsta
 *
 */
public interface CustomResponseTypesHandler {

    /**
     * Fail-fast method for finding out if the set of responses can be handled by this CustomResponseTypesHandler
     *
     * @param responseTypes the response types of an authorize request
     * @return true if the set of response types can be handles
     */
    boolean canHandleResponseTypes(Set<String> responseTypes);

    /**
     * Handle the custom response types authorization request
     *
     * @param authorizationRequest the approved AuthorizationRequest
     * @param authentication the authenticated user
     * @return a ModelAndView for either redirect, JSON response or any other custom handling
     */
    ModelAndView handleApprovedAuthorizationRequest(AuthorizationRequest authorizationRequest, Authentication authentication);
}
