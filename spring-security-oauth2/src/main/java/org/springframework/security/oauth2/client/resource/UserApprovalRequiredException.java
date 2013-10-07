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
package org.springframework.security.oauth2.client.resource;

import java.util.List;
import java.util.Map;

/**
 * Exception indicating that user approval is required, with some indication of how to signal the approval.
 * 
 * @author Dave Syer
 * 
 */
@SuppressWarnings("serial")
public class UserApprovalRequiredException extends RuntimeException {

	private final String approvalUri;

	private final Map<String, String> parameters;

	private final String clientId;

	private final List<String> scope;

	public UserApprovalRequiredException(String approvalUri, Map<String, String> parameters, String clientId, List<String> scope) {
		this.approvalUri = approvalUri;
		this.parameters = parameters;
		this.clientId = clientId;
		this.scope = scope;
	}

	/**
	 * @return the approvalUri the uri to which the user should submit for approval
	 */
	public String getApprovalUri() {
		return approvalUri;
	}

	/**
	 * Description of the parameters required to be submitted for approval. Map from the name of the parameter to its
	 * description.
	 * 
	 * @return the parameters the parameters required for approval
	 */
	public Map<String, String> getParameters() {
		return parameters;
	}

	/**
	 * @return the clientId the client that is requesting approval
	 */
	public String getClientId() {
		return clientId;
	}

	/**
	 * @return the scope the scope that has been requested for the token grant
	 */
	public List<String> getScope() {
		return scope;
	}

}
