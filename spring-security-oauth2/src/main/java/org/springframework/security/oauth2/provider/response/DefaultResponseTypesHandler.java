package org.springframework.security.oauth2.provider.response;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenRequest;
import org.springframework.util.Assert;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;

import java.util.Set;

/**
 * Default implementation of a ResponseTypesHandler that handles the 'code' and 'token' response types
 *
 * @author Okke Harsta
 */
public class DefaultResponseTypesHandler implements ResponseTypesHandler {

    private Object implicitLock = new Object();

    private AuthorizationRequestViewResolver authorizationRequestViewResolver = new DefaultAuthorizationRequestViewResolver();

    private TokenGranter tokenGranter;

    private OAuth2RequestFactory oAuth2RequestFactory;


    public DefaultResponseTypesHandler(TokenGranter tokenGranter, OAuth2RequestFactory oAuth2RequestFactory) {
        Assert.state(tokenGranter != null, "TokenGranter must be provided");
        Assert.state(oAuth2RequestFactory != null, "OAuth2RequestFactory must be provided");

        this.tokenGranter = tokenGranter;
        this.oAuth2RequestFactory = oAuth2RequestFactory;
    }

    @Override
    public boolean canHandleResponseTypes(Set<String> responseTypes) {
        return responseTypes.contains("token") || responseTypes.contains("code");
    }

    @Override
    public ModelAndView handleApprovedAuthorizationRequest(Set<String> responseTypes,
                                                           AuthorizationRequest authorizationRequest,
                                                           Authentication authentication,
                                                           AuthorizationCodeServices authorizationCodeServices)
            throws OAuth2Exception {
        try {
            if (responseTypes.contains("token")) {
                return getImplicitGrantResponse(authorizationRequest);
            }
            if (responseTypes.contains("code")) {
                return new ModelAndView(getAuthorizationCodeResponse(
                        authorizationRequest, authentication, authorizationCodeServices));
            }
            return handleUnsupportedResponseType(responseTypes, authorizationRequest, authentication);
        } catch (OAuth2Exception e) {
            View redirect = authorizationRequestViewResolver.getUnsuccessfulView(authorizationRequest, e);
            return new ModelAndView(redirect);
        }
    }

    protected ModelAndView handleUnsupportedResponseType(Set<String> responseTypes,
                                                         AuthorizationRequest authorizationRequest,
                                                         Authentication authentication) {
        throw new UnsupportedResponseTypeException("Unsupported response types: " + responseTypes);
    }

    // We can grant a token and return it with implicit approval.
    private ModelAndView getImplicitGrantResponse(AuthorizationRequest authorizationRequest) throws OAuth2Exception {
        TokenRequest tokenRequest = oAuth2RequestFactory.createTokenRequest(authorizationRequest, "implicit");
        OAuth2Request storedOAuth2Request = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);
        OAuth2AccessToken accessToken = getAccessTokenForImplicitGrant(tokenRequest, storedOAuth2Request);
        if (accessToken == null) {
            throw new UnsupportedResponseTypeException("Unsupported response type: token");
        }
        View view = authorizationRequestViewResolver.getSuccessfulImplicitGrantView(authorizationRequest, accessToken);
        return new ModelAndView(view);
    }

    private OAuth2AccessToken getAccessTokenForImplicitGrant(TokenRequest tokenRequest,
                                                             OAuth2Request storedOAuth2Request) {
        OAuth2AccessToken accessToken = null;
        // These 1 method calls have to be atomic, otherwise the ImplicitGrantService can have a race condition where
        // one thread removes the token request before another has a chance to redeem it.
        synchronized (this.implicitLock) {
            accessToken = tokenGranter.grant("implicit",
                    new ImplicitTokenRequest(tokenRequest, storedOAuth2Request));
        }
        return accessToken;
    }

    private View getAuthorizationCodeResponse(AuthorizationRequest authorizationRequest,
                                              Authentication authUser,
                                              AuthorizationCodeServices authorizationCodeServices) {
        try {
            OAuth2Request storedOAuth2Request = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);

            OAuth2Authentication combinedAuth = new OAuth2Authentication(storedOAuth2Request, authUser);
            String authorizationCode = authorizationCodeServices.createAuthorizationCode(combinedAuth);

            return authorizationRequestViewResolver.getSuccessfulAuthorizationCodeView(authorizationRequest, authorizationCode);

        } catch (OAuth2Exception e) {
            if (authorizationRequest.getState() != null) {
                e.addAdditionalInformation("state", authorizationRequest.getState());
            }
            throw e;
        }
    }

    public void setTokenGranter(TokenGranter tokenGranter) {
        this.tokenGranter = tokenGranter;
    }

    public void setOAuth2RequestFactory(OAuth2RequestFactory oAuth2RequestFactory) {
        this.oAuth2RequestFactory = oAuth2RequestFactory;
    }

    public void setAuthorizationRequestViewResolver(AuthorizationRequestViewResolver authorizationRequestViewResolver) {
        this.authorizationRequestViewResolver = authorizationRequestViewResolver;
    }
}
