/*
 * Copyright 2012-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.approval;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.provider.approval.Approval.ApprovalStatus;

/**
 * @author Dave Syer
 * 
 */
public abstract class AbstractTestApprovalStore {

	private ApprovalStore store;

	@Before
	public void setupStore() {
		store = getApprovalStore();
	}

	protected abstract ApprovalStore getApprovalStore();
	
	protected boolean addApprovals(Collection<Approval> approvals) {
		return store.addApprovals(approvals);
	}

	@Test
	public void testAddEmptyCollection() {
		assertTrue(addApprovals(Arrays.<Approval> asList()));
		assertEquals(0, store.getApprovals("foo", "bar").size());
	}

	@Test
	public void testAddDifferentScopes() {
		assertTrue(addApprovals(Arrays.<Approval> asList(new Approval("user", "client", "read", 1000,
				ApprovalStatus.APPROVED), new Approval("user", "client", "write", 1000, ApprovalStatus.APPROVED))));
		assertEquals(2, store.getApprovals("user", "client").size());
	}

	@Test
	public void testIdempotentAdd() {
		assertTrue(addApprovals(Arrays.<Approval> asList(new Approval("user", "client", "read", 1000,
				ApprovalStatus.APPROVED), new Approval("user", "client", "write", 1000, ApprovalStatus.APPROVED))));
		assertTrue(addApprovals(Arrays.<Approval> asList(new Approval("user", "client", "read", 1000,
				ApprovalStatus.APPROVED), new Approval("user", "client", "write", 1000, ApprovalStatus.APPROVED))));
		assertEquals(2, store.getApprovals("user", "client").size());
	}

	@Test
	public void testAddDifferentClients() {
		assertTrue(addApprovals(Arrays.<Approval> asList(new Approval("user", "client", "read", 1000,
				ApprovalStatus.APPROVED), new Approval("user", "other", "write", 1000, ApprovalStatus.APPROVED))));
		assertEquals(1, store.getApprovals("user", "client").size());
		assertEquals(1, store.getApprovals("user", "other").size());
	}

	@Test
	public void testVanillaRevoke() {
		Approval approval1 = new Approval("user", "client", "read", 1000, ApprovalStatus.APPROVED);
		Approval approval2 = new Approval("user", "client", "write", 1000, ApprovalStatus.APPROVED);
		assertTrue(addApprovals(Arrays.<Approval> asList(approval1, approval2)));
		store.revokeApprovals(Arrays.asList(approval1));
		assertEquals(getExpectedNumberOfApprovalsAfterRevoke(), store.getApprovals("user", "client").size());
	}

	protected int getExpectedNumberOfApprovalsAfterRevoke() {
		return 1;
	}

}
