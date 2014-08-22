/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.oauth.common;

import org.springframework.util.StringUtils;

import java.util.*;

/**
 * String utils for parsing authentication header.
 * Heavily based on code from deleted org.springframework.security.util.StringSplitUtils.
 *
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
public class StringSplitUtils {

	/**
	 * Splits a header into a map.
	 *
	 * @param header a header
	 * @return map of the header values
	 */
	public static Map<String, String> prepareHeaderForParsing(String header) {
		return splitEachArrayElementAndCreateMap(splitIgnoringQuotes(header, ','), "=", "\"");
	}

	/**
	 * Takes a list of <code>String</code>s, and for each element removes any instances of
	 * <code>removeCharacter</code>, and splits the element based on the <code>delimiter</code>. A <code>Map</code> is
	 * then generated, with the left of the delimiter providing the key, and the right of the delimiter providing the
	 * value.
	 *
	 * <p>Will trim both the key and value before adding to the <code>Map</code>.</p>
	 *
	 * @param array            the list to process
	 * @param delimiter        to split each element using (typically the equals symbol)
	 * @param removeCharacters one or more characters to remove from each element prior to attempting the split
	 *                         operation (typically the quotation mark symbol) or <code>null</code> if no removal should occur
	 * @return a <code>Map</code> representing the array contents, or <code>null</code> if the array to process was
	 * null or empty
	 */
	public static Map<String, String> splitEachArrayElementAndCreateMap(List<String> array, String delimiter, String removeCharacters) {
		if ((array == null) || (array.size() == 0)) {
			return null;
		}

		Map<String, String> map = new HashMap<String, String>();

		for (String item : array) {
			String postRemove;

			if (removeCharacters == null) {
				postRemove = item;
			}
			else {
				postRemove = StringUtils.replace(item, removeCharacters, "");
			}

			String[] splitThisArrayElement = StringUtils.split(postRemove, delimiter);

			if (splitThisArrayElement == null) {
				continue;
			}

			map.put(splitThisArrayElement[0].trim(), splitThisArrayElement[1].trim());
		}

		return map;
	}

	/**
	 * Splits a given string on the given separator character,
	 * skips the contents of quoted substrings when looking for separators.
	 * Introduced for use in DigestProcessingFilter (see SEC-506).
	 * <p/>
	 * This was copied and modified from commons-lang StringUtils
	 */
	public static List<String> splitIgnoringQuotes(String str, char separatorChar) {
		if (str == null) {
			return null;
		}

		int len = str.length();

		if (len == 0) {
			return Collections.emptyList();
		}

		List<String> list = new ArrayList<String>();
		int i = 0;
		int start = 0;
		boolean match = false;

		while (i < len) {
			if (str.charAt(i) == '"') {
				i++;
				while (i < len) {
					if (str.charAt(i) == '"') {
						i++;
						break;
					}
					i++;
				}
				match = true;
				continue;
			}
			if (str.charAt(i) == separatorChar) {
				if (match) {
					list.add(str.substring(start, i));
					match = false;
				}
				start = ++i;
				continue;
			}
			match = true;
			i++;
		}
		if (match) {
			list.add(str.substring(start, i));
		}

		return list;
	}
}