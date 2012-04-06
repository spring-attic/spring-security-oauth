package org.springframework.security.oauth2.common.util;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
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
