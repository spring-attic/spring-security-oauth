package org.springframework.security.oauth2.provider.exchange;

import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

/**
 * Created on 8/1/17.
 *
 * @author Ryan Murfitt (ryan.murfitt@console.com.au)
 */
public interface TokenExchangeService {
    Authentication loadUserAuthFromToken(TokenExchangeAuthenticationToken tokenAuth) throws AccountStatusException, InvalidTokenException;
}
