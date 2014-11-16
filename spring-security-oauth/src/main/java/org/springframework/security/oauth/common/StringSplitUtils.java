package org.springframework.security.oauth.common;

import org.springframework.util.StringUtils;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides several <code>String</code> manipulation methods. Copied from deleted org.springframework.security.util.StringSplitUtils
 */
public class StringSplitUtils {

  private static final String[] EMPTY_STRING_ARRAY = new String[0];

  /**
   * Splits a <code>String</code> at the first instance of the delimiter. Does not include the delimiter in
   * the response.
   *
   * @param toSplit   the string to split
   * @param delimiter to split the string up with
   * @return a two element array with index 0 being before the delimiter, and index 1 being after the delimiter
   *         (neither element includes the delimiter)
   * @throws IllegalArgumentException if an argument was invalid
   */
  public static String[] split(String toSplit, String delimiter) {
    Assert.hasLength(toSplit, "Cannot split a null or empty string");
    Assert.hasLength(delimiter, "Cannot use a null or empty delimiter to split a string");

    if (delimiter.length() != 1) {
      throw new IllegalArgumentException("Delimiter can only be one character in length");
    }

    int offset = toSplit.indexOf(delimiter);

    if (offset < 0) {
      return null;
    }

    String beforeDelimiter = toSplit.substring(0, offset);
    String afterDelimiter = toSplit.substring(offset + 1);

    return new String[]{beforeDelimiter, afterDelimiter};
  }

  /**
   * Takes an array of <code>String</code>s, and for each element removes any instances of
   * <code>removeCharacter</code>, and splits the element based on the <code>delimiter</code>. A <code>Map</code> is
   * then generated, with the left of the delimiter providing the key, and the right of the delimiter providing the
   * value. Will trim both the key and value before adding to the <code>Map</code>.
   *
   * @param array            the array to process
   * @param delimiter        to split each element using (typically the equals symbol)
   * @param removeCharacters one or more characters to remove from each element prior to attempting the split
   *                         operation (typically the quotation mark symbol) or <code>null</code> if no removal should occur
   * @return a <code>Map</code> representing the array contents, or <code>null</code> if the array to process was
   *         null or empty
   */
  public static Map<String, String> splitEachArrayElementAndCreateMap(String[] array, String delimiter, String removeCharacters) {
    if ((array == null) || (array.length == 0)) {
      return null;
    }

    Map<String, String> map = new HashMap<String, String>();

    for (int i = 0; i < array.length; i++) {
      String postRemove;

      if (removeCharacters == null) {
        postRemove = array[i];
      } else {
        postRemove = StringUtils.replace(array[i], removeCharacters, "");
      }

      String[] splitThisArrayElement = split(postRemove, delimiter);

      if (splitThisArrayElement == null) {
        continue;
      }

      map.put(splitThisArrayElement[0].trim(), splitThisArrayElement[1].trim());
    }

    return map;
  }

  /**
   * Splits a given string on the given separator character, skips the contents of quoted substrings
   * when looking for separators.
   * Introduced for use in DigestProcessingFilter (see SEC-506).
   *
   * This was copied and modified from commons-lang StringUtils
   * @param str the string to split
   * @param separatorChar the character by which to split the string
   * @return String array containing split string
   */
  public static String[] splitIgnoringQuotes(String str, char separatorChar) {
    if (str == null) {
      return null;
    }

    int len = str.length();

    if (len == 0) {
      return EMPTY_STRING_ARRAY;
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

    return list.toArray(new String[list.size()]);
  }

}
