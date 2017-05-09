package org.springframework.security.oauth2.provider.request;

import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.security.oauth2.provider.ResourceRequestDetails;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.util.Arrays.asList;
import static junit.framework.TestCase.assertEquals;

/**
 * @author Michael Kangas
 */
@RunWith(Parameterized.class)
public class InMemoryResourceRequestDetailsServiceTests {
  private static final Map<String, Map<String, Set<String>>> SCOPES = new HashMap<String, Map<String, Set<String>>>() {
    {
      for (Object[] row : new Object[][] {
              { ".*", "/rest/**", emptySet() },
              { "GET", "/**/objects/**", singleton("READ") },
              { "PUT", "/**/objects/**", singleton("CREATE") },
              { "POST", "/**/objects/**", singleton("UPDATE") },
              { "DELETE", "/**/objects/**", singleton("REMOVE") },
              { "PUT|POST|DELETE", "/**/administration/**", singleton("ADMINISTRATION") },
              { ".*", "/**/photos/**", toSet("PHOTOS", "PROFILE") }
      }) {
        Map<String, Set<String>> m = get(row[0]);
        if (m == null) {
          m = new HashMap<String, Set<String>>();
          put((String)row[0], m);
        }
        m.put((String)row[1], (Set)row[2]);
      }
    }
  };

  @Parameters
  public static Collection<Object[]> parameters() {
    return asList(new Object[][] {
            // wildcard matches:
            { emptySet(), "GET", "/rest" },  // no scope
            { emptySet(), "", "/rest/" },  // no scope
            { emptySet(), "FOO", "/rest/foobar" },  // no scope
            { null, "GET", "/foobar" },  // unmatched resource

            // typical matches:
            { singleton("READ"), "GET", "/rest/objects/documents" },
            { singleton("CREATE"), "PUT", "/rest/objects/documents" },

            // disjoint matches:
            { singleton("ADMINISTRATION"), "POST", "/administration" },
            { singleton("ADMINISTRATION"), "PUT", "/administration" },

            // multiple matches:
            { toSet("PHOTOS", "PROFILE"), "POST", "/photos" },
            { toSet("PROFILE", "READ", "PHOTOS"), "GET", "/objects/photos" }
    });
  }

  @Parameter
  public Set<String> expected;

  @Parameter(value = 1)
  public String requestMethod;

  @Parameter(value = 2)
  public String resourceURI;

  @Test
  public void testLoadResourceRequestDetails() {
    InMemoryResourceRequestDetailsService service = new InMemoryResourceRequestDetailsService();
    service.setRequestScopeStore(SCOPES);
    ResourceRequestDetails details = service.loadResourceRequestDetails(requestMethod, resourceURI);

    assertEquals(expected, details != null ? details.getScope() : null);
  }

  private static <E> Set<E> toSet(E... e) {
    return new HashSet<E>(asList(e));
  }
}
