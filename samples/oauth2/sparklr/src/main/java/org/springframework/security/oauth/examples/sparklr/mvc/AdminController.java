package org.springframework.security.oauth.examples.sparklr.mvc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth.examples.sparklr.oauth.SparklrUserApprovalHandler;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller for resetting the token store for testing purposes.
 * 
 * @author Dave Syer
 */
@Controller
public class AdminController {
	
	private static Log logger = LogFactory.getLog(AdminController.class);

	private InMemoryTokenStore tokenStore;
	
	private SparklrUserApprovalHandler userApprovalHandler;

	@RequestMapping("/oauth/cache_approvals")
	@ResponseBody
	public int startCaching() throws Exception {
		int count = 0;
		try {
			count = tokenStore.getAccessTokenCount();
		}
		catch (IllegalStateException e) {
			logger.error("Internal error in token store", e);
		}
		userApprovalHandler.setUseTokenServices(true);
		return count;
	}

	@RequestMapping("/oauth/uncache_approvals")
	@ResponseBody
	public int stopCaching() throws Exception {
		int count = 0;
		try {
			count = tokenStore.getAccessTokenCount();
		}
		catch (IllegalStateException e) {
			logger.error("Internal error in token store", e);
		}
		userApprovalHandler.setUseTokenServices(false);
		return count;
	}

	/**
	 * @param tokenStore the tokenStore to set
	 */
	public void setTokenStore(InMemoryTokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}
	
	/**
	 * @param userApprovalHandler the userApprovalHandler to set
	 */
	public void setUserApprovalHandler(SparklrUserApprovalHandler userApprovalHandler) {
		this.userApprovalHandler = userApprovalHandler;
	}

}
