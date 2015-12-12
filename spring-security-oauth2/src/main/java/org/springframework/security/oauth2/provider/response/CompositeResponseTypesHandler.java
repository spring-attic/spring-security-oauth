package org.springframework.security.oauth2.provider.response;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.util.Assert;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;
import java.util.Set;

/**
 * Implementation of ResponseTypesHandler which stacks multiple ResponseTypesHandler instances.
 *
 * @author Okke Harsta
 */
public class CompositeResponseTypesHandler implements ResponseTypesHandler {

    private final List<ResponseTypesHandler> responseTypesHandlers;

    public CompositeResponseTypesHandler(List<ResponseTypesHandler> responseTypesHandlers) {
        Assert.notNull(responseTypesHandlers, "responseTypesHandlers is null");
        this.responseTypesHandlers = responseTypesHandlers;
    }

    @Override
    public boolean canHandleResponseTypes(Set<String> responseTypes) {
        for (ResponseTypesHandler handler : responseTypesHandlers) {
            boolean canHandle = handler.canHandleResponseTypes(responseTypes);
            if (canHandle) {
                return true;
            }
        }
        return false;
    }

    @Override
    public ModelAndView handleApprovedAuthorizationRequest(Set<String> responseTypes,
                                                           AuthorizationRequest authorizationRequest,
                                                           Authentication authentication,
                                                           AuthorizationCodeServices authorizationCodeServices) {
        for (ResponseTypesHandler handler : responseTypesHandlers) {
            boolean canHandle = handler.canHandleResponseTypes(responseTypes);
            if (canHandle) {
                return handler.handleApprovedAuthorizationRequest(responseTypes,
                        authorizationRequest, authentication, authorizationCodeServices);
            }
        }
        throw new UnsupportedResponseTypeException("Unsupported response types: " + authorizationRequest.getResponseTypes());
    }
}
