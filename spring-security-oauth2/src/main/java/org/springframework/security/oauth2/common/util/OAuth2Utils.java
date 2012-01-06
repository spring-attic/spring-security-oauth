package org.springframework.security.oauth2.common.util;

import java.util.Arrays;
import java.util.Collection;
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
		if (values != null) {
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
}
