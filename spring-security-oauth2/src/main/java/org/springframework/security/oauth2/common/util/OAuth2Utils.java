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
	 * Parses a string value into a scope.
	 * 
	 * @param scopeValue The value of the scope.
	 * @return The scope.
	 */
	public static Set<String> parseScope(String scopeValue) {
		Set<String> scope = new TreeSet<String>();
		if (scopeValue != null) {
			// the spec says the scope is separated by spaces, but Facebook uses commas, so we'll include commas, too.
			String[] tokens = scopeValue.split("[\\s+,]");
			scope.addAll(Arrays.asList(tokens));
		}
		return scope;
	}

	/**
	 * Formats a scope value into a String.
	 * 
	 * @param scopeValue The value of the scope.
	 * @return The scope formatted for form submission etc, or null if the input is empty
	 */
	public static String formatScope(Collection<String> scope) {
		return scope==null ? null : StringUtils.collectionToDelimitedString(scope, " ");
	}
}
