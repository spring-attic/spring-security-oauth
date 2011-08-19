/**
 * 
 */
package org.springframework.security.oauth2.provider.client;

import java.util.Set;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.provider.AccessGrantAuthenticationToken;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

/**
 * @author jricher
 *
 */
public class ClientCredentialsAuthenticationToken extends AbstractAuthenticationToken {

	private final ClientAuthenticationToken clientAuthentication;

	  public ClientCredentialsAuthenticationToken(String clientId, String clientSecret, Set<String> scope) {
	    super(null);
	    this.clientAuthentication = new AccessGrantAuthenticationToken(clientId, clientSecret, scope, "client_credentials");
	  }

	  public ClientAuthenticationToken getClientAuthentication() {
	    return clientAuthentication;
	  }

	  public Object getPrincipal() {
	    return this.clientAuthentication.getPrincipal();
	  }

	  public Object getCredentials() {
	    return this.clientAuthentication.getCredentials();
	  }

	  @Override
	  public void setDetails(Object details) {
	    super.setDetails(details);
	    this.clientAuthentication.setDetails(details);
	  }

}
