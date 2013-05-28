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
package org.springframework.security.oauth2.common.util;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.util.StringUtils;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public abstract class OAuth2Utils {

	/**
	 * Parses a string parameter value into a set of strings.
	 * 
	 * @param values The values of the set.
	 * @return The set.
	 */
	public static Set<String> parseParameterList(String values) {
		Set<String> result = new TreeSet<String>();
		if (values != null && values.trim().length() > 0) {
			// the spec says the scope is separated by spaces, but Facebook uses commas, so we'll include commas, too.
			String[] tokens = values.split("[\\s+,]");
			result.addAll(Arrays.asList(tokens));
		}
		return result;
	}

	/**
	 * Validate the scope provided by the client. Called by the {@link AuthorizationEndpoint} and also by the
	 * {@link TokenEndpoint} before a response is sent back to the client. Note that during an authorization code flow
	 * both endpoints will call this method, but the TokenEndpoint in that case has very little if anything to validate
	 * since all the parameters needed for the access token were provided to the AuthorizationEndpoint.
	 * 
	 * @param parameters the request parameters
	 * @param clientDetails the client requesting the token
	 */
	//TODO: should this be removed to its own validation class to improve extensibility?
	public static void validateScope(Map<String, String> parameters, Set<String> clientScopes) {
		if (parameters.containsKey("scope")) {
			if (clientScopes != null && !clientScopes.isEmpty()) {
				for (String scope : parseParameterList(parameters.get("scope"))) {
					if (!clientScopes.contains(scope)) {
						throw new InvalidScopeException("Invalid scope: " + scope, clientScopes);
					}
				}
			}
		}
	}
	
	/**
	 * Formats a set of string values into a format appropriate for sending as a single-valued form value.
	 * 
	 * @param value The value of the parameter.
	 * @return The value formatted for form submission etc, or null if the input is empty
	 */
	public static String formatParameterList(Collection<String> value) {
		return value == null ? null : StringUtils.collectionToDelimitedString(value, " ");
	}

	/**
	 * Extract a map from a query string.
	 * 
	 * @param query a query (or fragment) string from a URI
	 * @return a Map of the values in the query
	 */
	public static Map<String, String> extractMap(String query) {
		Map<String, String> map = new HashMap<String, String>();
		Properties properties = StringUtils.splitArrayElementsIntoProperties(
				StringUtils.delimitedListToStringArray(query, "&"), "=");
		if (properties != null) {
			for (Object key : properties.keySet()) {
				map.put(key.toString(), properties.get(key).toString());
			}
		}
		return map;
	}
}
