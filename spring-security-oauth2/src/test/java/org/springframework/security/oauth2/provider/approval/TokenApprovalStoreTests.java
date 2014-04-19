/*
 * Copyright 2012-2013 the original author or authors.
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

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * @author Dave Syer
 *
 */
public class TokenApprovalStoreTests extends AbstractTestApprovalStore {
	
	private TokenApprovalStore store = new TokenApprovalStore();
	private InMemoryTokenStore tokenStore = new InMemoryTokenStore();

	@Override
	protected ApprovalStore getApprovalStore() {
		store.setTokenStore(tokenStore);
		return store ;
	}
	
	@Override
	protected boolean addApprovals(Collection<Approval> approvals) {

		Map<String, Map<String, Set<String>>> clientIds = new HashMap<String, Map<String,Set<String>>>();
		for (Approval approval : approvals) {
			String clientId = approval.getClientId();
			if (!clientIds.containsKey(clientId)) {
				clientIds.put(clientId, new HashMap<String, Set<String>>());
			}
			String userId = approval.getUserId();
			Map<String, Set<String>> users = clientIds.get(clientId);
			if (!users.containsKey(userId)) {
				users.put(userId, new HashSet<String>());
			}
			Set<String> scopes = users.get(userId);
			scopes.add(approval.getScope());
		}

		for (String clientId : clientIds.keySet()) {
			Map<String, Set<String>> users = clientIds.get(clientId);
			for (String userId : users.keySet()) {
				Authentication user = new UsernamePasswordAuthenticationToken(userId, "N/A", AuthorityUtils.commaSeparatedStringToAuthorityList("USER"));
				AuthorizationRequest authorizationRequest = new AuthorizationRequest();
				authorizationRequest.setClientId(clientId);
				Set<String> scopes = users.get(userId);
				authorizationRequest.setScope(scopes);
				OAuth2Request request = authorizationRequest.createOAuth2Request();
				OAuth2Authentication authentication = new OAuth2Authentication(request, user);
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(UUID.randomUUID().toString());
				token.setScope(scopes);
				tokenStore.storeAccessToken(token, authentication);				
			}
		}
		return super.addApprovals(approvals);
	}

	protected int getExpectedNumberOfApprovalsAfterRevoke() {
		return 0;
	}
}
