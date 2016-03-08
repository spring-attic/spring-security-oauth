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

import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.approval.Approval.ApprovalStatus;
import org.springframework.util.Assert;

/**
 * A user approval handler that remembers approval decisions by consulting existing approvals.
 * 
 * @author Dave Syer
 * 
 */
public class ApprovalStoreUserApprovalHandler implements UserApprovalHandler, InitializingBean {

	private static Log logger = LogFactory.getLog(ApprovalStoreUserApprovalHandler.class);

	private String scopePrefix = OAuth2Utils.SCOPE_PREFIX;

	private ApprovalStore approvalStore;

	private int approvalExpirySeconds = -1;

	private ClientDetailsService clientDetailsService;

	/**
	 * Service to load client details (optional) for auto approval checks.
	 * 
	 * @param clientDetailsService a client details service
	 */
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	/**
	 * The prefix applied to incoming parameters that signal approval or denial of a scope.
	 * 
	 * @param scopePrefix the prefix (default {@link OAuth2Utils#SCOPE_PREFIX})
	 */
	public void setScopePrefix(String scopePrefix) {
		this.scopePrefix = scopePrefix;
	}

	/**
	 * @param store the approval to set
	 */
	public void setApprovalStore(ApprovalStore store) {
		this.approvalStore = store;
	}

	private OAuth2RequestFactory requestFactory;

	public void setRequestFactory(OAuth2RequestFactory requestFactory) {
		this.requestFactory = requestFactory;
	}

	public void setApprovalExpiryInSeconds(int approvalExpirySeconds) {
		this.approvalExpirySeconds = approvalExpirySeconds;
	}

	public void afterPropertiesSet() {
		Assert.state(approvalStore != null, "ApprovalStore must be provided");
		Assert.state(requestFactory != null, "OAuth2RequestFactory must be provided");
	}

	public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
		return authorizationRequest.isApproved();
	}

	public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
			Authentication userAuthentication) {

		String clientId = authorizationRequest.getClientId();
		Collection<String> requestedScopes = authorizationRequest.getScope();
		Set<String> approvedScopes = new HashSet<String>();
		Set<String> validUserApprovedScopes = new HashSet<String>();

		if (clientDetailsService != null) {
			try {
				ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
				for (String scope : requestedScopes) {
					if (client.isAutoApprove(scope)) {
						approvedScopes.add(scope);
					}
				}
				if (approvedScopes.containsAll(requestedScopes)) {
					authorizationRequest.setApproved(true);
					return authorizationRequest;
				}
			}
			catch (ClientRegistrationException e) {
				logger.warn("Client registration problem prevent autoapproval check for client=" + clientId);
			}
		}

		if (logger.isDebugEnabled()) {
			StringBuilder builder = new StringBuilder("Looking up user approved authorizations for ");
			builder.append("client_id=" + clientId);
			builder.append(" and username=" + userAuthentication.getName());
			logger.debug(builder.toString());
		}

		// Find the stored approvals for that user and client
		Collection<Approval> userApprovals = approvalStore.getApprovals(userAuthentication.getName(), clientId);

		// Look at the scopes and see if they have expired
		Date today = new Date();
		for (Approval approval : userApprovals) {
			if (approval.getExpiresAt().after(today)) {
				if (approval.getStatus() == ApprovalStatus.APPROVED) {
					validUserApprovedScopes.add(approval.getScope());
					approvedScopes.add(approval.getScope());
				}
			}
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Valid user approved/denied scopes are " + validUserApprovedScopes);
		}

		// If the requested scopes have already been acted upon by the user,
		// this request is approved
		if (validUserApprovedScopes.containsAll(requestedScopes)) {
			approvedScopes.retainAll(requestedScopes);
			// Set only the scopes that have been approved by the user
			authorizationRequest.setScope(approvedScopes);
			authorizationRequest.setApproved(true);
		}

		return authorizationRequest;

	}

	private Date computeExpiry() {
		Calendar expiresAt = Calendar.getInstance();
		if (approvalExpirySeconds == -1) { // use default of 1 month
			expiresAt.add(Calendar.MONTH, 1);
		}
		else {
			expiresAt.add(Calendar.SECOND, approvalExpirySeconds);
		}
		return expiresAt.getTime();
	}

	/**
	 * Requires the authorization request to be explicitly approved, including all individual scopes, and the user to be
	 * authenticated. A scope that was requested in the authorization request can be approved by sending a request
	 * parameter <code>scope.&lt;scopename&gt;</code> equal to "true" or "approved" (otherwise it will be assumed to
	 * have been denied). The {@link ApprovalStore} will be updated to reflect the inputs.
	 * 
	 * @param authorizationRequest The authorization request.
	 * @param userAuthentication the current user authentication
	 * 
	 * @return An approved request if all scopes have been approved by the current user.
	 */
	public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
			Authentication userAuthentication) {
		// Get the approved scopes
		Set<String> requestedScopes = authorizationRequest.getScope();
		Set<String> approvedScopes = new HashSet<String>();
		Set<Approval> approvals = new HashSet<Approval>();

		Date expiry = computeExpiry();

		// Store the scopes that have been approved / denied
		Map<String, String> approvalParameters = authorizationRequest.getApprovalParameters();
		for (String requestedScope : requestedScopes) {
			String approvalParameter = scopePrefix + requestedScope;
			String value = approvalParameters.get(approvalParameter);
			value = value == null ? "" : value.toLowerCase();
			if ("true".equals(value) || value.startsWith("approve")) {
				approvedScopes.add(requestedScope);
				approvals.add(new Approval(userAuthentication.getName(), authorizationRequest.getClientId(),
						requestedScope, expiry, ApprovalStatus.APPROVED));
			}
			else {
				approvals.add(new Approval(userAuthentication.getName(), authorizationRequest.getClientId(),
						requestedScope, expiry, ApprovalStatus.DENIED));
			}
		}
		approvalStore.addApprovals(approvals);

		boolean approved;
		authorizationRequest.setScope(approvedScopes);
		if (approvedScopes.isEmpty() && !requestedScopes.isEmpty()) {
			approved = false;
		}
		else {
			approved = true;
		}
		authorizationRequest.setApproved(approved);
		return authorizationRequest;
	}

	@Override
	public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest,
			Authentication userAuthentication) {
		Map<String, Object> model = new HashMap<String, Object>();
		model.putAll(authorizationRequest.getRequestParameters());
		Map<String, String> scopes = new LinkedHashMap<String, String>();
		for (String scope : authorizationRequest.getScope()) {
			scopes.put(OAuth2Utils.SCOPE_PREFIX + scope, "false");
		}
		for (Approval approval : approvalStore.getApprovals(userAuthentication.getName(),
				authorizationRequest.getClientId())) {
			if (authorizationRequest.getScope().contains(approval.getScope())) {
				scopes.put(OAuth2Utils.SCOPE_PREFIX + approval.getScope(),
						approval.getStatus() == ApprovalStatus.APPROVED ? "true" : "false");
			}
		}
		model.put("scopes", scopes);
		return model;
	}
}
