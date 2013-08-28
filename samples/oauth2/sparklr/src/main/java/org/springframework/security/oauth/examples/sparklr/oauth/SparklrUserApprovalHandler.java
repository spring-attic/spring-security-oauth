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

package org.springframework.security.oauth.examples.sparklr.oauth;

import java.util.Collection;
import java.util.HashSet;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler;

/**
 * @author Dave Syer
 * 
 */
public class SparklrUserApprovalHandler extends TokenStoreUserApprovalHandler {

	private Collection<String> autoApproveClients = new HashSet<String>();

	private boolean useTokenServices = true;

	/**
	 * @param useTokenServices the useTokenServices to set
	 */
	public void setUseTokenServices(boolean useTokenServices) {
		this.useTokenServices = useTokenServices;
	}

	/**
	 * @param autoApproveClients the auto approve clients to set
	 */
	public void setAutoApproveClients(Collection<String> autoApproveClients) {
		this.autoApproveClients = autoApproveClients;
	}

	/**
	 * Allows automatic approval for a white list of clients in the implicit grant case.
	 * 
	 * @param authorizationRequest The authorization request.
	 * @param userAuthentication the current user authentication
	 * 
	 * @return An updated request if it has already been approved by the current user.
	 */
	@Override
	public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
			Authentication userAuthentication) {

		boolean approved = false;
		// If we are allowed to check existing approvals this will short circuit the decision
		if (useTokenServices) {
			authorizationRequest = super.checkForPreApproval(authorizationRequest, userAuthentication);
			approved = authorizationRequest.isApproved();
		}
		else if (!userAuthentication.isAuthenticated()) {
			approved = false;
		}
		else {
			approved = (authorizationRequest.getResponseTypes().contains("token") && autoApproveClients
					.contains(authorizationRequest.getClientId()));
		}
		authorizationRequest.setApproved(approved);

		return authorizationRequest;

	}

}
