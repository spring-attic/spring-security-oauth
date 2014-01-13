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
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import org.springframework.util.StringUtils;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public abstract class OAuth2Utils {

	/**
	 * Constant to use while parsing and formatting parameter maps for OAuth2 requests
	 */
	public static final String CLIENT_ID = "client_id";

	/**
	 * Constant to use while parsing and formatting parameter maps for OAuth2 requests
	 */
	public static final String STATE = "state";

	/**
	 * Constant to use while parsing and formatting parameter maps for OAuth2 requests
	 */
	public static final String SCOPE = "scope";

	/**
	 * Constant to use while parsing and formatting parameter maps for OAuth2 requests
	 */
	public static final String REDIRECT_URI = "redirect_uri";

	/**
	 * Constant to use while parsing and formatting parameter maps for OAuth2 requests
	 */
	public static final String RESPONSE_TYPE = "response_type";

	/**
	 * Constant to use while parsing and formatting parameter maps for OAuth2 requests
	 */
	public static final String USER_OAUTH_APPROVAL = "user_oauth_approval";

	/**
	 * Constant to use as a prefix for scope approval
	 */
	public static final String SCOPE_PREFIX = "scope.";

	/**
	 * Constant to use while parsing and formatting parameter maps for OAuth2 requests
	 */
	public static final String GRANT_TYPE = "grant_type";

	/**
	 * Parses a string parameter value into a set of strings.
	 * 
	 * @param values The values of the set.
	 * @return The set.
	 */
	public static Set<String> parseParameterList(String values) {
		Set<String> result = new TreeSet<String>();
		if (values != null && values.trim().length() > 0) {
			// the spec says the scope is separated by spaces
			String[] tokens = values.split("[\\s+]");
			result.addAll(Arrays.asList(tokens));
		}
		return result;
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

	/**
	 * Compare 2 sets and check that one contains all members of the other.
	 * 
	 * @param target set of strings to check
	 * @param members the members to compare to
	 * @return true if all members are in the target
	 */
	public static boolean containsAll(Set<String> target, Set<String> members) {
		target = new HashSet<String>(target);
		target.retainAll(members);
		return target.size() == members.size();
	}
}
