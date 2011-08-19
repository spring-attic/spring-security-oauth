package org.springframework.security.oauth2.common.util;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author Ryan Heaton
 */
public class OAuth2Utils {

  private OAuth2Utils() {}

  /**
   * Parses a string value into a scope.
   *
   * @param scopeValue The value of the scope.
   * @return The scope.
   */
  public static Set<String> parseScope(String scopeValue) {
    Set<String> scope = new TreeSet<String>();
    if (scopeValue != null) {
      //the spec says the scope is separated by spaces, but Facebook uses commas, so we'll include commas, too.
      String[] tokens = scopeValue.split("[\\s+,]");
      scope.addAll(Arrays.asList(tokens));
    }
    return scope;
  }
}
