package org.springframework.security.oauth2.provider.request;

import static java.util.regex.Pattern.matches;

import org.springframework.security.oauth2.provider.ResourceRequestDetails;
import org.springframework.security.oauth2.provider.ResourceRequestDetailsService;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * In-memory implementation of a resource request details service.  Pattern matching on method (regex) and request
 * URI ({@link PathMatcher}) facilitates compact representation of method-->resource-->scope mappings.
 *
 * @author Michael Kangas
 */
public class InMemoryResourceRequestDetailsService implements ResourceRequestDetailsService {
  private Map<String, Map<String, Set<String>>> requestScopeStore = new HashMap<String, Map<String, Set<String>>>();
  private PathMatcher pathMatcher = new AntPathMatcher();

  public void setRequestScopeStore(Map<String, Map<String, Set<String>>> requestScopeStore) {
    this.requestScopeStore = requestScopeStore;
  }

  public void setPathMatcher(PathMatcher pathMatcher) {
    this.pathMatcher = pathMatcher;
  }

  /**
   * Loads the details of the requested resource whose request method and URI match at least one configured pattern.
   * The method is regex-matched against the stored patterns, while the request URI is path-matched.
   *
   * <p>
   * All scopes that are found across all successful matches are included in the result.
   *
   * @param method     the request method
   * @param requestURI the request URI
   * @return the details of the resource request or {@code null} if none are found (i.e., there are no matches)
   */
  @Override
  public ResourceRequestDetails loadResourceRequestDetails(final String method, final String requestURI) {
    Set<Set<String>> scopes = new HashSet<Set<String>>();
    for (Map<String, Set<String>> r : filter(requestScopeStore, method).values()) {
      scopes.addAll(filter(r, requestURI, pathMatcher).values());
    }

    if (scopes.isEmpty()) {
      return null;
    }

    final Set<String> scope = new HashSet<String>();
    for (Set<String> s : scopes) {
      scope.addAll(s);
    }

    return new ResourceRequestDetails() {
      public Set<String> getScope() {
        return scope;
      }

      public String getMethod() {
        return method;
      }

      public String getURI() {
        return requestURI;
      }
    };
  }

  /**
   * Filters a map whose keys are patterns that match the argument test.  If a {@link PathMatcher} is supplied, it is
   * used to do the match (i.e., as a path); otherwise, {@link Pattern}{@code .matches()} is used (i.e., as a regex).
   *
   * @param map map whose keys represent patterns (path or regex)
   * @param test string to match for filtering
   * @param m optional path matcher to use for path matching (all but the first are ignored)
   * @return sub-map whose keys match {@code test}
   */
  private static <V> Map<String, V> filter(Map<String, V> map, String test, PathMatcher... m) {
    Map<String, V> result = new HashMap<String, V>();
    for (String k : map.keySet()) {
      if (m.length > 0 ? m[0].match(k, test) : matches(k, test)) {
        result.put(k, map.get(k));
      }
    }
    return result;
  }
}
