package org.springframework.security.oauth2.provider.response;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.web.servlet.ModelAndView;

import java.util.Set;

/**
 * Default Noop implementation of CustomResponseTypesHandler which does not handle any custom response types.
 *
 * @author Okke Harsta
 */
public class NoopCustomResponseTypesHandler implements CustomResponseTypesHandler {

    @Override
    public boolean canHandleResponseTypes(Set<String> responseTypes) {
        return false;
    }

    @Override
    public ModelAndView handleApprovedAuthorizationRequest(AuthorizationRequest authorizationRequest, Authentication authentication) {
        throw new UnsupportedResponseTypeException("No custom response types are supported. Unsupported response types: " + authorizationRequest.getResponseTypes());
    }
}
