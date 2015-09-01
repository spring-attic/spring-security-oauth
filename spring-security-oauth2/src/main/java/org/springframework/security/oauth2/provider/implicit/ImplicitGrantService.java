package org.springframework.security.oauth2.provider.implicit;

import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;

/**
 * Service to associate &amp; store an incoming AuthorizationRequest with the TokenRequest that is passed
 * to the ImplicitTokenGranter during the Implicit flow. This mimics the AuthorizationCodeServices
 * functionality from the Authorization Code flow, allowing the ImplicitTokenGranter to reference the original 
 * AuthorizationRequest, while still allowing the ImplicitTokenGranter to adhere to the TokenGranter interface. 
 * 
 * @author Amanda Anganes
 * 
 * @deprecated with no replacement (it shouldn't be necessary to use this strategy since 2.0.2)
 *
 */
@Deprecated
public interface ImplicitGrantService {

	/**
	 * Save an association between an OAuth2Request and a TokenRequest.
	 * 
	 * @param originalRequest
	 * @param tokenRequest
	 */
	public void store(OAuth2Request originalRequest, TokenRequest tokenRequest);
	
	/**
	 * Look up and return the OAuth2Request associated with the given TokenRequest.
	 * 
	 * @param tokenRequest
	 * @return
	 */
	public OAuth2Request remove(TokenRequest tokenRequest);
	
}
