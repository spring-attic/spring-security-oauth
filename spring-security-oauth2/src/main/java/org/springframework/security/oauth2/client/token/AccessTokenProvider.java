/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.token;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

/**
 * A strategy which knows how to obtain an access token for a specific resource.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public interface AccessTokenProvider {

	/**
	 * Obtain a new access token for the specified protected resource.
	 * 
	 * @param details The protected resource for which this provider is to obtain an access token.
	 * @param parameters The parameters of the request giving context for the token details if any.
	 * @return The access token for the specified protected resource. The return value may NOT be null.
	 * @throws UserRedirectRequiredException If the provider requires the current user to be redirected for
	 * authorization.
	 * @throws UserApprovalRequiredException If the provider is ready to issue a token but only if the user approves
	 * @throws AccessDeniedException If the user denies access to the protected resource.
	 */
	OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest parameters)
			throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException;

	/**
	 * Whether this provider supports the specified resource.
	 * 
	 * @param resource The resource.
	 * @return Whether this provider supports the specified resource.
	 */
	boolean supportsResource(OAuth2ProtectedResourceDetails resource);

	/**
	 * @param resource the resource for which a token refresh is required
	 * @param refreshToken the refresh token to send
	 * @return an access token
	 */
	OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource, OAuth2RefreshToken refreshToken,
			AccessTokenRequest request) throws UserRedirectRequiredException;

	/**
	 * @param resource The resource to check
	 * @return true if this provider can refresh an access token
	 */
	boolean supportsRefresh(OAuth2ProtectedResourceDetails resource);
}
