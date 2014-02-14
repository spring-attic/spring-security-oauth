package org.springframework.security.oauth.examples.sparklr.mvc;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth.examples.sparklr.oauth.SparklrUserApprovalHandler;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Controller for resetting the token store for testing purposes.
 * 
 * @author Dave Syer
 */
@Controller
public class AdminController {

	private ConsumerTokenServices tokenServices;
	
	private TokenStore tokenStore;

	private SparklrUserApprovalHandler userApprovalHandler;

	@RequestMapping("/oauth/cache_approvals")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void startCaching() throws Exception {
		userApprovalHandler.setUseApprovalStore(true);
	}

	@RequestMapping("/oauth/uncache_approvals")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void stopCaching() throws Exception {
		userApprovalHandler.setUseApprovalStore(false);
	}

	@RequestMapping("/oauth/users/{user}/tokens")
	@ResponseBody
	public Collection<OAuth2AccessToken> listTokensForUser(@PathVariable String user, Principal principal)
			throws Exception {
		checkResourceOwner(user, principal);
		return enhance(tokenStore.findTokensByUserName(user));
	}

	@RequestMapping(value = "/oauth/users/{user}/tokens/{token}", method = RequestMethod.DELETE)
	public ResponseEntity<Void> revokeToken(@PathVariable String user, @PathVariable String token, Principal principal)
			throws Exception {
		checkResourceOwner(user, principal);
		if (tokenServices.revokeToken(token)) {
			return new ResponseEntity<Void>(HttpStatus.NO_CONTENT);
		} else {
			return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);			
		}
	}

	@RequestMapping("/oauth/clients/{client}/tokens")
	@ResponseBody
	public Collection<OAuth2AccessToken> listTokensForClient(@PathVariable String client) throws Exception {
		return enhance(tokenStore.findTokensByClientId(client));
	}

	private Collection<OAuth2AccessToken> enhance(Collection<OAuth2AccessToken> tokens) {
		Collection<OAuth2AccessToken> result = new ArrayList<OAuth2AccessToken>();
		for (OAuth2AccessToken prototype : tokens) {
			DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(prototype);
			String clientId = tokenStore.readAuthentication(token).getOAuth2Request().getClientId();
			if (clientId != null) {
				Map<String, Object> map = new HashMap<String, Object>(token.getAdditionalInformation());
				map.put("client_id", clientId);
				token.setAdditionalInformation(map);
				result.add(token);
			}
		}
		return result;
	}

	private void checkResourceOwner(String user, Principal principal) {
		if (principal instanceof OAuth2Authentication) {
			OAuth2Authentication authentication = (OAuth2Authentication) principal;
			if (!authentication.isClientOnly() && !user.equals(principal.getName())) {
				throw new AccessDeniedException(String.format("User '%s' cannot obtain tokens for user '%s'",
						principal.getName(), user));
			}
		}
	}

	/**
	 * @param userApprovalHandler the userApprovalHandler to set
	 */
	public void setUserApprovalHandler(SparklrUserApprovalHandler userApprovalHandler) {
		this.userApprovalHandler = userApprovalHandler;
	}

	/**
	 * @param tokenServices the consumerTokenServices to set
	 */
	public void setTokenServices(ConsumerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}
	
	/**
	 * @param tokenStore the tokenStore to set
	 */
	public void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

}
