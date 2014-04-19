/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.springframework.security.oauth2.provider.endpoint;

import java.security.Principal;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * OAuth2 token services that produces JWT encoded token values.
 * 
 * @author Dave Syer
 * @author Luke Taylor
 * @author Joel D'sa
 */
@FrameworkEndpoint
public class TokenKeyEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());

    private JwtAccessTokenConverter converter;

 	public TokenKeyEndpoint(JwtAccessTokenConverter converter) {
		super();
		this.converter = converter;
	}

    /**
     * Get the verification key for the token signatures. The principal has to
     * be provided only if the key is secret
     * (shared not public).
     * 
     * @param principal the currently authenticated user if there is one
     * @return the key used to verify tokens
     */
    @RequestMapping(value = "/oauth/token_key", method = RequestMethod.GET)
    @ResponseBody
    public Map<String, String> getKey(Principal principal) {
        if ((principal == null || principal instanceof AnonymousAuthenticationToken) && !converter.isPublic()) {
            throw new AccessDeniedException("You need to authenticate to see a shared key");
        }
        Map<String, String> result = converter.getKey();
        return result;
    }

}
