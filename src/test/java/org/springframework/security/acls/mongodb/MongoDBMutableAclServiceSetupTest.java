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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.DomainObjectPermission;
import org.springframework.security.acls.domain.MongoAcl;
import org.springframework.security.acls.domain.MongoSid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * @author Roman Vottner
 * @since 4.3
 */
class MongoDBMutableAclServiceSetupTest extends SetupTestMongoDBAcl {

	@Autowired
	private MongoDBMutableAclService aclService;

	@AfterEach
	public void cleanup() {
		aclRepository.deleteAll();
	}

	@Test
	@WithMockUser
	public void testCreateAcl() throws Exception {
		// Arrange
		TestDomainObject domainObject = new TestDomainObject();

		// Act
		ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());
		Acl acl = aclService.createAcl(objectIdentity);

		// Assert
		assertThat(acl).isNotNull();
		assertThat(acl.getObjectIdentity().getIdentifier()).isEqualTo(domainObject.getId());
		assertThat(acl.getObjectIdentity().getType()).isEqualTo(domainObject.getClass().getName());
		assertThat(acl.getOwner()).isEqualTo(new PrincipalSid(SecurityContextHolder.getContext().getAuthentication().getName()));
	}

	@Test
	@WithMockUser
	public void testDeleteAcl() throws Exception {
		// Arrange
		TestDomainObject domainObject = new TestDomainObject();
		ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

		MongoAcl mongoAcl = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(),
				UUID.randomUUID().toString(), new MongoSid(SecurityContextHolder.getContext().getAuthentication().getName()),
				null, true);
		DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
				new MongoSid(SecurityContextHolder.getContext().getAuthentication().getName()),
				BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
				true, true, true);
		mongoAcl.getPermissions().add(permission);

		aclRepository.save(mongoAcl);

		// Act
		aclService.deleteAcl(objectIdentity, true);

		// Assert
		MongoAcl afterDelete = aclRepository.findById(mongoAcl.getId()).orElse(null);
		assertThat(afterDelete).isNull();
	}

	@Test
	@WithMockUser
	public void testDeleteAcl_includingChildren() throws Exception {
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
		aclService.deleteAcl(objectIdentity, true);

		// Assert
		MongoAcl afterDelete = aclRepository.findById(parent.getId()).orElse(null);
		assertThat(afterDelete).isNull();
		List<MongoAcl> remaining = aclRepository.findAll();
		assertThat(remaining.size()).isEqualTo(1);
		assertThat(remaining.get(0).getId()).isEqualTo(nonChild.getId());
	}

	@Test
	@WithMockUser
	public void testDeleteAcl_excludingChildren() throws Exception {
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
		try {
			aclService.deleteAcl(objectIdentity, false);
			fail("Should have thrown an exception as removing a parent ACL is not allowed");
		} catch (Exception ex) {
			assertThat(ex).isInstanceOf(ChildrenExistException.class);
		}
	}

	@Test
	@WithMockUser
	public void testUpdateAcl() throws Exception {
		// Arrange
		TestDomainObject domainObject = new TestDomainObject();
		ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

		MongoAcl mongoAcl = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(),
				UUID.randomUUID().toString(), new MongoSid(SecurityContextHolder.getContext().getAuthentication().getName()),
				null, true);
		DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
				new MongoSid(SecurityContextHolder.getContext().getAuthentication().getName()),
				BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
				true, true, true);
		mongoAcl.getPermissions().add(permission);
		aclRepository.save(mongoAcl);

		MutableAcl updatedAcl = (MutableAcl) aclService.readAclById(objectIdentity);
		updatedAcl.insertAce(updatedAcl.getEntries().size(), BasePermission.ADMINISTRATION, new PrincipalSid("Sam Sample"), true);

		// Act
		aclService.updateAcl(updatedAcl);

		// Assert
		MongoAcl updated = aclRepository.findById(mongoAcl.getId()).orElse(null);
		assertThat(updated).isNotNull();
		assertThat(updated.getPermissions().size()).isEqualTo(2);
		assertThat(updated.getPermissions().get(0).getId()).isEqualTo(permission.getId());
		assertThat(updated.getPermissions().get(1).getPermission()).isEqualTo(BasePermission.ADMINISTRATION.getMask());
		assertThat(updated.getPermissions().get(1).getSid().getName()).isEqualTo("Sam Sample");
		assertThat(updated.getPermissions().get(1).getSid().isPrincipal()).isTrue();
	}
}
