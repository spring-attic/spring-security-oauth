/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.client.token;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.util.MultiValueMap;

public class DefaultRequestEnhancer implements RequestEnhancer {

	private Set<String> parameterIncludes = Collections.emptySet();
	
	public void setParameterIncludes(Collection<String> parameterIncludes) {
		this.parameterIncludes = new LinkedHashSet<String>(parameterIncludes);
	}

	@Override
	public void enhance(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form, HttpHeaders headers) {
		for (String include : parameterIncludes) {
			if (request.containsKey(include)) {
				form.set(include, request.getFirst(include));
			}
		}
	}

}
