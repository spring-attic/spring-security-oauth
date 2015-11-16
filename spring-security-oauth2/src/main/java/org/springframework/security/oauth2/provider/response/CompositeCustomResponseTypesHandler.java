package org.springframework.security.oauth2.provider.response;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.util.Assert;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;
import java.util.Set;

/**
 * Implementation of CustomResponseTypesHandler which stacks multiple CustomResponseTypesHandler instances.
 *
 * @author Okke Harsta
 */
public class CompositeCustomResponseTypesHandler implements CustomResponseTypesHandler{

    private final List<CustomResponseTypesHandler> customResponseTypesHandlers;

    public CompositeCustomResponseTypesHandler(List<CustomResponseTypesHandler> customResponseTypesHandlers) {
        Assert.notNull(customResponseTypesHandlers, "customResponseTypesHandlers is null");
        this.customResponseTypesHandlers = customResponseTypesHandlers;
    }

    @Override
    public boolean canHandleResponseTypes(Set<String> responseTypes) {
        for (CustomResponseTypesHandler handler : customResponseTypesHandlers) {
            boolean canHandle = handler.canHandleResponseTypes(responseTypes);
            if (canHandle) {
                return true;
            }
        }
        return false;
    }

    @Override
    public ModelAndView handleApprovedAuthorizationRequest(AuthorizationRequest authorizationRequest, Authentication authentication) {
        for (CustomResponseTypesHandler handler : customResponseTypesHandlers) {
            boolean canHandle = handler.canHandleResponseTypes(authorizationRequest.getResponseTypes());
            if (canHandle) {
                return handler.handleApprovedAuthorizationRequest(authorizationRequest, authentication);
            }
        }
        throw new UnsupportedResponseTypeException("No custom response types are supported. Unsupported response types: " + authorizationRequest.getResponseTypes());
    }
}
