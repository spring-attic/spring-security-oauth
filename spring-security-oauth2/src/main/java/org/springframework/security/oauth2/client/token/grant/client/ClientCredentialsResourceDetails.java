package org.springframework.security.oauth2.client.token.grant.client;

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;

/**
 * @author Dave Syer
 */
public class ClientCredentialsResourceDetails extends BaseOAuth2ProtectedResourceDetails {
	
	public ClientCredentialsResourceDetails() {
		setGrantType("client_credentials");
	}
	
	@Override
	public boolean isClientOnly() {
		return true;
	}

}
