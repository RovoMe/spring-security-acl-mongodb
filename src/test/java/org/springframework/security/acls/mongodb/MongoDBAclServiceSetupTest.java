/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.acls.mongodb;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.DomainObjectPermission;
import org.springframework.security.acls.domain.MongoAcl;
import org.springframework.security.acls.domain.MongoSid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Contains tests for retrieving ACLs via a {@link MongoDBAclService} instance.
 *
 * @author Roman Vottner
 * @since 4.3
 */
public class MongoDBAclServiceSetupTest extends SetupTestMongoDBAcl {

	@Autowired
	private AclService aclService;

	@Autowired
	private MongoTemplate mongoTemplate;

	/**
	 * Tests the retrieval of child domain objects by providing a representation of the parent domain object holder.
	 * Note the current implementation does filter duplicate children.
	 */
	@Test
	@WithMockUser
	public void testFindChildren() throws Exception {
		// Arrange
		TestDomainObject domainObject = new TestDomainObject();
		TestDomainObject child1DomainObject = new TestDomainObject();
		TestDomainObject child2DomainObject = new TestDomainObject();
		TestDomainObject otherDomainObject = new TestDomainObject();
		TestDomainObject unreladedDomainObject = new TestDomainObject();

		MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString());
		MongoAcl child1 = new MongoAcl(child1DomainObject.getId(), child1DomainObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Tim Test"), parent.getId(), true);
		MongoAcl child2 = new MongoAcl(child2DomainObject.getId(), child2DomainObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parent.getId(), true);
		MongoAcl child3 = new MongoAcl(otherDomainObject.getId(), otherDomainObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Sam Sample"), parent.getId(), true);
		MongoAcl nonChild = new MongoAcl(unreladedDomainObject.getId(), unreladedDomainObject.getClass().getName(), UUID.randomUUID().toString());

		mongoTemplate.save(parent);
		mongoTemplate.save(child1);
		mongoTemplate.save(child2);
		mongoTemplate.save(child3);
		mongoTemplate.save(nonChild);

		// Act
		ObjectIdentity parentIdentity = new ObjectIdentityImpl(Class.forName(parent.getClassName()), parent.getInstanceId());
		List<ObjectIdentity> children = aclService.findChildren(parentIdentity);

		// Assert
		assertThat(children.size()).isEqualTo(3);
		assertThat(children.get(0).getIdentifier()).isEqualTo(child1DomainObject.getId());
		assertThat(children.get(0).getType()).isEqualTo(child1DomainObject.getClass().getName());
		assertThat(children.get(1).getIdentifier()).isEqualTo(child2DomainObject.getId());
		assertThat(children.get(1).getType()).isEqualTo(child2DomainObject.getClass().getName());
		assertThat(children.get(2).getIdentifier()).isEqualTo(otherDomainObject.getId());
		assertThat(children.get(2).getType()).isEqualTo(otherDomainObject.getClass().getName());
	}

	/**
	 * This test assumes that ACLs can be retrieved via {@link AclService#readAclById(ObjectIdentity)} method.
	 *
	 * @throws Exception any exception thrown during the test are propagated further. No exception handling is done in
	 *                   the test
	 */
	@Test
	@WithMockUser
	public void testReadAclById() throws Exception {

		// Arrange
		int readWritePermissions = BasePermission.READ.getMask() | BasePermission.WRITE.getMask();
		int readWriteCreatePermissions = BasePermission.READ.getMask() | BasePermission.WRITE.getMask() | BasePermission.CREATE.getMask();

		TestDomainObject parentObject = new TestDomainObject();
		TestDomainObject domainObject = new TestDomainObject();

		MongoAcl parentAcl = new MongoAcl(parentObject.getId(), parentObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Check Norris"), null, true);
		MongoAcl mongoAcl = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parentAcl.getId(), true);
		List<DomainObjectPermission> permissions = new ArrayList<>();
		permissions.add(new DomainObjectPermission(UUID.randomUUID().toString(), new MongoSid("Sam Sample"),
				readWritePermissions, true, false, true));
		permissions.add(new DomainObjectPermission(UUID.randomUUID().toString(), new MongoSid("Tim Test"),
				readWriteCreatePermissions, true, false, true));
		mongoAcl.setPermissions(permissions);

		mongoTemplate.save(parentAcl);
		mongoTemplate.save(mongoAcl);

		// Act
		ObjectIdentity parentIdentity = new ObjectIdentityImpl(Class.forName(parentAcl.getClassName()), parentAcl.getInstanceId());
		ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(mongoAcl.getClassName()), mongoAcl.getInstanceId());
		Acl pAcl = aclService.readAclById(parentIdentity);
		Acl acl = aclService.readAclById(objectIdentity);

		// Assert
		assertThat(acl.getObjectIdentity().getIdentifier()).isEqualTo(domainObject.getId());
		assertThat(acl.getObjectIdentity().getType()).isEqualTo(domainObject.getClass().getName());
		assertThat(acl.getParentAcl()).isEqualTo(pAcl);
		assertThat(acl.getEntries().size()).isEqualTo(2);
		assertThat(acl.getEntries().get(0).getSid()).isEqualTo(new PrincipalSid("Sam Sample"));
		assertThat(acl.getEntries().get(0).getPermission().getMask()).isEqualTo(readWritePermissions);
		assertThat(acl.getOwner()).isEqualTo(new PrincipalSid("Petty Pattern"));
		assertThat(acl.isEntriesInheriting()).isTrue();
	}

	/**
	 * This test assumes that ACLs can be retrieved via {@link AclService#readAclById(ObjectIdentity, List)} by
	 * providing a list of {@link Sid Sids}.
	 *
	 * @throws Exception any unexpected exception are propagated further
	 */
	@Test
	@WithMockUser
	public void testReadAclsById_ForSpecifiedSids() throws Exception {

		// Arrange
		TestDomainObject domainObject = new TestDomainObject();
		TestDomainObject firstObject = new TestDomainObject();
		TestDomainObject secondObject = new TestDomainObject();
		TestDomainObject thirdObject = new TestDomainObject();
		TestDomainObject unrelatedObject = new TestDomainObject();

		MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString());
		MongoAcl child1 = new MongoAcl(firstObject.getId(), firstObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Tim Test"), parent.getId(), true);
		MongoAcl child2 = new MongoAcl(secondObject.getId(), secondObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parent.getId(), true);
		MongoAcl child3 = new MongoAcl(thirdObject.getId(), thirdObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Sam Sample"), parent.getId(), true);
		MongoAcl nonChild = new MongoAcl(unrelatedObject.getId(), unrelatedObject.getClass().getName(), UUID.randomUUID().toString());

		DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
				new MongoSid(SecurityContextHolder.getContext().getAuthentication().getName()),
				BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
				true, true, true);

		parent.getPermissions().add(permission);
		child1.getPermissions().add(permission);
		child2.getPermissions().add(permission);

		aclRepository.save(parent);
		aclRepository.save(child1);
		aclRepository.save(child2);
		aclRepository.save(child3);
		aclRepository.save(nonChild);

		// Act
		List<Sid> sids = new ArrayList<>();
		sids.add(new PrincipalSid("Tim Test")); // first object owner
		sids.add(new PrincipalSid("Sam Sample")); // third object owner

		ObjectIdentity parentIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());
		ObjectIdentity firstObjectIdentity = new ObjectIdentityImpl(Class.forName(firstObject.getClass().getName()), firstObject.getId());
		ObjectIdentity secondObjectIdentity = new ObjectIdentityImpl(Class.forName(secondObject.getClass().getName()), secondObject.getId());
		ObjectIdentity thirdObjectIdentity = new ObjectIdentityImpl(Class.forName(thirdObject.getClass().getName()), thirdObject.getId());

		// Quote from AclService's Javadoc:
		//     "The returned map is keyed on the passed objects, with the values being the <tt>Acl</tt> instances. Any
		//      unknown objects (or objects for which the interested <tt>Sid</tt>s do not have entries) will not have a
		//      map key."
		// The verification in AclService though throws a NotFoundException if an ACL for a given ObjectIdentity could
		// not be obtained!

		// neither the parent ...
		try {
			aclService.readAclsById(Collections.singletonList(parentIdentity), sids);
			fail("Should have thrown a NotFoundException as no ACL should be obtainable as the parent ACL does not " +
					"define permissions for any identity provided in the given list");
		} catch (Exception ex) {
			assertThat(ex).isInstanceOf(NotFoundException.class);
		}
		// ... nor a sibling which do not specify any of the provided sids in the permissions (or owner) shall be
		// obtainable
		try {
			aclService.readAclsById(Arrays.asList(firstObjectIdentity, secondObjectIdentity, thirdObjectIdentity), sids);
			fail("Should have thrown a NotFoundException as no ACL should be obtainable for the second object identity " +
					"passed in due to not specifying any of the provided security identities");
		} catch (Exception ex) {
			assertThat(ex).isInstanceOf(NotFoundException.class);
		}

		Map<ObjectIdentity, Acl> acl = aclService.readAclsById(Arrays.asList(firstObjectIdentity, thirdObjectIdentity), sids);

		// Assert
		assertThat(acl).containsOnlyKeys(firstObjectIdentity, thirdObjectIdentity);
	}

	/**
	 * This test assumes that ACLs inherit the permission of the parent ACL if inheritance is configured on the child.
	 *
	 * @throws Exception any unexpected exception are propagated further
	 */
	@Test
	@WithMockUser
	public void testReadAclsById_checkChildAclIsInheritingPermissions() throws Exception {
		// Arrange
		TestDomainObject domainObject = new TestDomainObject();
		TestDomainObject firstObject = new TestDomainObject();
		TestDomainObject secondObject = new TestDomainObject();
		TestDomainObject thirdObject = new TestDomainObject();
		TestDomainObject unrelatedObject = new TestDomainObject();

		ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

		MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString());
		MongoAcl child1 = new MongoAcl(firstObject.getId(), firstObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Tim Test"), parent.getId(), true);
		MongoAcl child2 = new MongoAcl(secondObject.getId(), secondObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parent.getId(), true);
		MongoAcl child3 = new MongoAcl(thirdObject.getId(), thirdObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Sam Sample"), parent.getId(), true);
		MongoAcl nonChild = new MongoAcl(unrelatedObject.getId(), unrelatedObject.getClass().getName(), UUID.randomUUID().toString());

		DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
				new MongoSid(SecurityContextHolder.getContext().getAuthentication().getName()),
				BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
				true, true, true);

		parent.getPermissions().add(permission);
		child1.getPermissions().add(permission);
		child2.getPermissions().add(permission);

		aclRepository.save(parent);
		aclRepository.save(child1);
		aclRepository.save(child2);
		aclRepository.save(child3);
		aclRepository.save(nonChild);

		// Act
		List<Sid> sids = new LinkedList<>();
		sids.add(new PrincipalSid(SecurityContextHolder.getContext().getAuthentication().getName()));
		sids.add(new PrincipalSid("Tim Test"));

		List<ObjectIdentity> childObjects = aclService.findChildren(objectIdentity);
		Map<ObjectIdentity, Acl> resultUser = aclService.readAclsById(childObjects, sids);

		// Assert
		// The default constructor on the parent ACL sets the owner to the authenticated user by default though the
		// parent also specifies permission for the current user explicitly. As permissions are looked up on ancestors
		// in case `entriesInheriting` is set to true, the 3rd child is also retrieved here as well
		assertThat(resultUser.keySet().size()).isEqualTo(3);
	}

	/**
	 * This test assumes that inherited ACLs are complete.
	 *
	 * @throws Exception any unexpected exception are propagated further
	 */
	@Test
	@WithMockUser
	public void testReadAclsById_checkAclContainsProperInheritanceStructure() throws Exception {
		// Arrange
		TestDomainObject domainObject = new TestDomainObject();
		TestDomainObject firstObject = new TestDomainObject();
		TestDomainObject secondObject = new TestDomainObject();
		TestDomainObject thirdObject = new TestDomainObject();
		TestDomainObject unrelatedObject = new TestDomainObject();

		ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

		MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("owner"), null, true);
		MongoAcl child1 = new MongoAcl(firstObject.getId(), firstObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Tim Test"), parent.getId(), true);
		MongoAcl child2 = new MongoAcl(secondObject.getId(), secondObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parent.getId(), true);
		MongoAcl child3 = new MongoAcl(thirdObject.getId(), thirdObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Sam Sample"), parent.getId(), true);
		MongoAcl nonChild = new MongoAcl(unrelatedObject.getId(), unrelatedObject.getClass().getName(), UUID.randomUUID().toString());

		DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
				new MongoSid(SecurityContextHolder.getContext().getAuthentication().getName()),
				BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
				true, true, true);

		parent.getPermissions().add(permission);
		child1.getPermissions().add(permission);
		child2.getPermissions().add(permission);

		aclRepository.save(parent);
		aclRepository.save(child1);
		aclRepository.save(child2);
		aclRepository.save(child3);
		aclRepository.save(nonChild);

		// Act
		List<Sid> sids = new LinkedList<>();
		sids.add(new PrincipalSid(SecurityContextHolder.getContext().getAuthentication().getName()));

		List<ObjectIdentity> childObjects = aclService.findChildren(objectIdentity);
		Map<ObjectIdentity, Acl> resultUser = aclService.readAclsById(childObjects, sids);

		// Assert
		assertThat(childObjects.size()).isEqualTo(3);
		assertThat(resultUser.keySet().size()).isEqualTo(3);
		// permissions for the 3rd child are inherited from its parent though not copied to the child directly! A
		// permission evaluator therefore has to check whether isEntriesInheriting is true and check the ancestors for
		// permissions as well
		resultUser.keySet().forEach(objectIdentity1 -> {
			Acl acl = resultUser.get(objectIdentity1);
			checkPermissions(acl);
		});
	}

	@Test
	@WithMockUser
	public void issue3_testReadAclsByIdTwice() throws Exception {
		// Arrange
		TestDomainObject domainObject = new TestDomainObject();
		TestDomainObject firstObject = new TestDomainObject();
		TestDomainObject secondObject = new TestDomainObject();
		TestDomainObject thirdObject = new TestDomainObject();
		TestDomainObject unrelatedObject = new TestDomainObject();

		ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

		MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("owner"), null, true);
		MongoAcl child1 = new MongoAcl(firstObject.getId(), firstObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Tim Test"), parent.getId(), true);
		MongoAcl child2 = new MongoAcl(secondObject.getId(), secondObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parent.getId(), true);
		MongoAcl child3 = new MongoAcl(thirdObject.getId(), thirdObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Sam Sample"), parent.getId(), true);
		MongoAcl nonChild = new MongoAcl(unrelatedObject.getId(), unrelatedObject.getClass().getName(), UUID.randomUUID().toString());

		DomainObjectPermission user0Permissions = new DomainObjectPermission(UUID.randomUUID().toString(),
				new MongoSid("user-0"),
				BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
				true, true, true);
		DomainObjectPermission user1Permissions = new DomainObjectPermission(UUID.randomUUID().toString(),
				new MongoSid("user-1"),
				BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
				true, true, true);

		// child3 inherits permission of parent
		parent.getPermissions().add(user0Permissions);
		child1.getPermissions().add(user0Permissions);
		child2.getPermissions().add(user0Permissions);

		// child3 has no permission to inherit from
		child1.getPermissions().add(user1Permissions);
		child2.getPermissions().add(user1Permissions);

		aclRepository.save(parent);
		aclRepository.save(child1);
		aclRepository.save(child2);
		aclRepository.save(child3);
		aclRepository.save(nonChild);

		// Act
		List<Sid> sids = new LinkedList<>();
		sids.add(new PrincipalSid("owner"));

		List<Sid> sids1 = new LinkedList<>();
		sids1.add(new PrincipalSid("user-0"));

		List<Sid> sids2 = new LinkedList<>();
		sids2.add(new PrincipalSid("user-1"));

		List<ObjectIdentity> childObjects = aclService.findChildren(objectIdentity);

		Map<ObjectIdentity, Acl> resultOwner = aclService.readAclsById(childObjects, sids);
		Map<ObjectIdentity, Acl> resultUser = aclService.readAclsById(childObjects, sids1);
		try {
			aclService.readAclsById(childObjects, sids2);
			fail("Method should have thrown a NotFoundException as child3 ACL does not define any permissions for user-1");
		} catch (Exception ex) {
			assertThat(ex).isInstanceOf(NotFoundException.class);
		}

		// Assert
		assertThat(childObjects.size()).isEqualTo(3);
		assertThat(resultUser.keySet().size()).isEqualTo(3);
		resultUser.keySet().forEach(objectIdentity1 -> {
			Acl acl = resultUser.get(objectIdentity1);
			checkPermissions(acl);
		});
		assertThat(resultUser.keySet().size()).isEqualTo(3);

		assertThat(resultOwner).isEqualTo(resultUser);
	}

	private void checkPermissions(Acl acl) {
		Set<AccessControlEntry> permissions = new LinkedHashSet<>();
		Acl _parent = acl.getParentAcl();
		if (acl.isEntriesInheriting()) {
			while (null != _parent) {
				permissions.addAll(_parent.getEntries());
				if (_parent.isEntriesInheriting()) {
					_parent = _parent.getParentAcl();
				}
			}
		}

		assertThat(permissions.size()).as("ACE %s did not contain or inherit the correct permissions", acl)
				.isEqualTo(1);
	}
}
