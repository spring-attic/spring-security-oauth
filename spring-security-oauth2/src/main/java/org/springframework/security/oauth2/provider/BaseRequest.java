/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.springframework.security.oauth2.provider;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * @author Dave Syer
 * 
 */
public class BaseRequest implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * Resolved client ID. This may be present in the original request parameters, or in some cases may be inferred by a
	 * processing class and inserted here.
	 */
	private String clientId;

	/**
	 * Resolved scope set, initialized (by the OAuth2RequestFactory) with the scopes originally requested. Further
	 * processing and user interaction may alter the set of scopes that is finally granted and stored when the request
	 * processing is complete.
	 */
	private Set<String> scope = new HashSet<String>();

	/**
	 * Map of parameters passed in to the Authorization Endpoint or Token Endpoint, preserved unchanged from the
	 * original request. This map should not be modified after initialization. In general, classes should not retrieve
	 * values from this map directly, and should instead use the individual members on this class.
	 * 
	 * The OAuth2RequestFactory is responsible for initializing all members of this class, usually by parsing the values
	 * inside the requestParmaeters map.
	 * 
	 */
	private Map<String, String> requestParameters = Collections.unmodifiableMap(new HashMap<String, String>());
	
	public BaseRequest(String clientId) {
		this.clientId = clientId;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public Set<String> getScope() {
		return scope;
	}

	public void setScope(Collection<String> scope) {
		if (scope != null && scope.size() == 1) {
			String value = scope.iterator().next();
			/*
			 * This is really an error, but it can catch out unsuspecting users and it's easy to fix. It happens when an
			 * AuthorizationRequest gets bound accidentally from request parameters using @ModelAttribute.
			 */
			if (value.contains(" ") || scope.contains(",")) {
				scope = OAuth2Utils.parseParameterList(value);
			}
		}
		this.scope = Collections.unmodifiableSet(scope == null ? new LinkedHashSet<String>()
				: new LinkedHashSet<String>(scope));
	}

	/**
	 * Warning: most clients should use the individual properties of this class, such as {{@link #getScope()} or {
	 * {@link #getClientId()}, rather than retrieving values from this map.
	 * 
	 * @return the original, unchanged set of request parameters
	 */
	public Map<String, String> getRequestParameters() {
		return requestParameters;
	}

	public void setRequestParameters(Map<String, String> requestParameters) {
		if (requestParameters != null) {
			this.requestParameters = Collections.unmodifiableMap(requestParameters);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((clientId == null) ? 0 : clientId.hashCode());
		result = prime * result + ((requestParameters == null) ? 0 : requestParameters.hashCode());
		result = prime * result + ((scope == null) ? 0 : scope.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		BaseRequest other = (BaseRequest) obj;
		if (clientId == null) {
			if (other.clientId != null)
				return false;
		}
		else if (!clientId.equals(other.clientId))
			return false;
		if (requestParameters == null) {
			if (other.requestParameters != null)
				return false;
		}
		else if (!requestParameters.equals(other.requestParameters))
			return false;
		if (scope == null) {
			if (other.scope != null)
				return false;
		}
		else if (!scope.equals(other.scope))
			return false;
		return true;
	}

}
