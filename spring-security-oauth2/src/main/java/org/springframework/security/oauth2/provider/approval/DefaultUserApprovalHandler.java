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

package org.springframework.security.oauth2.provider.approval;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;

/**
 * A default user approval handler that doesn't remember any decisions.
 * 
 * @author Dave Syer
 * 
 */
public class DefaultUserApprovalHandler implements UserApprovalHandler {

	private String approvalParameter = OAuth2Utils.USER_OAUTH_APPROVAL;
	
	/**
	 * @param approvalParameter the approvalParameter to set
	 */
	public void setApprovalParameter(String approvalParameter) {
		this.approvalParameter = approvalParameter;
	}

	/**
	 * Basic implementation just requires the authorization request to be explicitly approved and the user to be
	 * authenticated.
	 * 
	 * @param authorizationRequest The authorization request.
	 * @param userAuthentication the current user authentication
	 * 
	 * @return Whether the specified request has been approved by the current user.
	 */
	public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
		if (authorizationRequest.isApproved()) {
			return true;
		}
		return false;
	}

	public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
		return authorizationRequest;
	}

	@Override
	public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
		Map<String, String> approvalParameters = authorizationRequest.getApprovalParameters();
		String flag = approvalParameters.get(approvalParameter);
		boolean approved = flag != null && flag.toLowerCase().equals("true");
		authorizationRequest.setApproved(approved);
		return authorizationRequest;
	}
	
	@Override
	public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest,
			Authentication userAuthentication) {
		Map<String, Object> model = new HashMap<String, Object>();
		// In case of a redirect we might want the request parameters to be included
		model.putAll(authorizationRequest.getRequestParameters());
		return model;
	}

}
