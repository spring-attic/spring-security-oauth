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
 * 
 * A base class for the three "*Request" classes used in processing OAuth 2
 * authorizations. This class should <strong>never</strong> be used directly,
 * and it should <strong>never</strong> be used as the type for a local or other
 * variable.
 * 
 * @author Dave Syer
 * 
 */
@SuppressWarnings("serial")
abstract class BaseRequest implements Serializable {

	/**
	 * Resolved client ID. This may be present in the original request
	 * parameters, or in some cases may be inferred by a processing class and
	 * inserted here.
	 */
	private String clientId;

	/**
	 * Resolved scope set, initialized (by the OAuth2RequestFactory) with the
	 * scopes originally requested. Further processing and user interaction may
	 * alter the set of scopes that is finally granted and stored when the
	 * request processing is complete.
	 */
	private Set<String> scope = new HashSet<String>();

	/**
	 * Map of parameters passed in to the Authorization Endpoint or Token
	 * Endpoint, preserved unchanged from the original request. This map should
	 * not be modified after initialization. In general, classes should not
	 * retrieve values from this map directly, and should instead use the
	 * individual members on this class.
	 * 
	 * The OAuth2RequestFactory is responsible for initializing all members of
	 * this class, usually by parsing the values inside the requestParmaeters
	 * map.
	 * 
	 */
	private Map<String, String> requestParameters = Collections
			.unmodifiableMap(new HashMap<String, String>());

	public String getClientId() {
		return clientId;
	}

	public Set<String> getScope() {
		return scope;
	}

	/**
	 * Warning: most clients should use the individual properties of this class,
	 * such as {{@link #getScope()} or { {@link #getClientId()}, rather than
	 * retrieving values from this map.
	 * 
	 * @return the original, unchanged set of request parameters
	 */
	public Map<String, String> getRequestParameters() {
		return requestParameters;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((clientId == null) ? 0 : clientId.hashCode());
		result = prime
				* result
				+ ((requestParameters == null) ? 0 : requestParameters
						.hashCode());
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
		} else if (!clientId.equals(other.clientId))
			return false;
		if (requestParameters == null) {
			if (other.requestParameters != null)
				return false;
		} else if (!requestParameters.equals(other.requestParameters))
			return false;
		if (scope == null) {
			if (other.scope != null)
				return false;
		} else if (!scope.equals(other.scope))
			return false;
		return true;
	}

	protected void setScope(Collection<String> scope) {
		if (scope != null && scope.size() == 1) {
			String value = scope.iterator().next();
			/*
			 * This is really an error, but it can catch out unsuspecting users
			 * and it's easy to fix. It happens when an AuthorizationRequest
			 * gets bound accidentally from request parameters using
			 * @ModelAttribute.
			 */
			if (value.contains(" ") || value.contains(",")) {
				scope = OAuth2Utils.parseParameterList(value);
			}
		}
		this.scope = Collections
				.unmodifiableSet(scope == null ? new LinkedHashSet<String>()
						: new LinkedHashSet<String>(scope));
	}

	protected void setRequestParameters(Map<String, String> requestParameters) {
		if (requestParameters != null) {
			this.requestParameters = Collections
					.unmodifiableMap(requestParameters);
		}
	}

	protected void setClientId(String clientId) {
		this.clientId = clientId;
	}

}
