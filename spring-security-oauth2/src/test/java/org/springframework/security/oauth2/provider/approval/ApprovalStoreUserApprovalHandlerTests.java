package org.springframework.security.oauth2.provider.approval;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

public class ApprovalStoreUserApprovalHandlerTests {

	private ApprovalStoreUserApprovalHandler handler = new ApprovalStoreUserApprovalHandler();

	private InMemoryApprovalStore store = new InMemoryApprovalStore();
	
	private InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

	private Authentication userAuthentication;

	@Before
	public void init() {
		handler.setApprovalStore(store);
		InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
		Map<String, ClientDetails> map = new HashMap<String, ClientDetails>();
		map.put("client", new BaseClientDetails("client", null, "read,write", "authorization_code", null));
		clientDetailsService.setClientDetailsStore(map);
		handler.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
		userAuthentication = new UsernamePasswordAuthenticationToken("user", "N/A",
				AuthorityUtils.commaSeparatedStringToAuthorityList("USER"));
	}
	
	@Test
	public void testApprovalLongExpiry() throws Exception {
		handler.setApprovalExpiryInSeconds(365*24*60*60);
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("client", Arrays.asList("read"));
		authorizationRequest.setApprovalParameters(Collections.singletonMap("scope.read", "approved"));
		AuthorizationRequest result = handler.updateAfterApproval(authorizationRequest, userAuthentication);
		assertTrue(handler.isApproved(result, userAuthentication));		
	}

	@Test
	public void testExplicitlyApprovedScopes() {
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("client", Arrays.asList("read"));
		authorizationRequest.setApprovalParameters(Collections.singletonMap("scope.read", "approved"));
		AuthorizationRequest result = handler.updateAfterApproval(authorizationRequest, userAuthentication);
		assertTrue(handler.isApproved(result, userAuthentication));
		assertEquals(1, store.getApprovals("user", "client").size());
		assertEquals(1, result.getScope().size());
		assertTrue(result.isApproved());
	}

	@Test
	public void testImplicitlyDeniedScope() {
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("client", Arrays.asList("read", "write"));
		authorizationRequest.setApprovalParameters(Collections.singletonMap("scope.read", "approved"));
		AuthorizationRequest result = handler.updateAfterApproval(authorizationRequest, userAuthentication);
		assertTrue(handler.isApproved(result, userAuthentication));
		Collection<Approval> approvals = store.getApprovals("user", "client");
		assertEquals(2, approvals.size());
		approvals.contains(new Approval("user", "client", "read", new Date(), Approval.ApprovalStatus.APPROVED));
		approvals.contains(new Approval("user", "client", "write", new Date(), Approval.ApprovalStatus.DENIED));
		assertEquals(1, result.getScope().size());
	}

	@Test
	public void testExplicitlyPreapprovedScopes() {
		store.addApprovals(Arrays.asList(new Approval("user", "client", "read", new Date(
				System.currentTimeMillis() + 10000), Approval.ApprovalStatus.APPROVED)));
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("client", Arrays.asList("read"));
		AuthorizationRequest result = handler.checkForPreApproval(authorizationRequest, userAuthentication);
		assertTrue(result.isApproved());
	}

	@Test
	public void testExplicitlyUnapprovedScopes() {
		store.addApprovals(Arrays.asList(new Approval("user", "client", "read", new Date(
				System.currentTimeMillis() + 10000), Approval.ApprovalStatus.DENIED)));
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("client", Arrays.asList("read"));
		AuthorizationRequest result = handler.checkForPreApproval(authorizationRequest, userAuthentication);
		assertFalse(result.isApproved());
	}

	@Test
	public void testAutoapprovedScopes() {
		handler.setClientDetailsService(clientDetailsService);
		BaseClientDetails client = new BaseClientDetails("client", null, "read", "authorization_code", null);
		client.setAutoApproveScopes(new HashSet<String>(Arrays.asList("read")));
		clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", client));
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("client", Arrays.asList("read"));
		AuthorizationRequest result = handler.checkForPreApproval(authorizationRequest, userAuthentication);
		assertTrue(result.isApproved());
	}

	@Test
	public void testAutoapprovedWildcardScopes() {
		handler.setClientDetailsService(clientDetailsService);
		BaseClientDetails client = new BaseClientDetails("client", null, "read", "authorization_code", null);
		client.setAutoApproveScopes(new HashSet<String>(Arrays.asList(".*")));
		clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", client));
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("client", Arrays.asList("read"));
		AuthorizationRequest result = handler.checkForPreApproval(authorizationRequest, userAuthentication);
		assertTrue(result.isApproved());
	}

	@Test
	public void testAutoapprovedAllScopes() {
		handler.setClientDetailsService(clientDetailsService);
		BaseClientDetails client = new BaseClientDetails("client", null, "read", "authorization_code", null);
		client.setAutoApproveScopes(new HashSet<String>(Arrays.asList("true")));
		clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", client));
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("client", Arrays.asList("read"));
		AuthorizationRequest result = handler.checkForPreApproval(authorizationRequest, userAuthentication);
		assertTrue(result.isApproved());
	}

	@Test
	public void testExpiredPreapprovedScopes() {
		store.addApprovals(Arrays.asList(new Approval("user", "client", "read", new Date(
				System.currentTimeMillis() - 10000), Approval.ApprovalStatus.APPROVED)));
		AuthorizationRequest authorizationRequest = new AuthorizationRequest("client", Arrays.asList("read"));
		AuthorizationRequest result = handler.checkForPreApproval(authorizationRequest, userAuthentication);
		assertFalse(result.isApproved());
	}

}
