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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.acls.dao.AclRepository;
import org.springframework.security.acls.domain.MongoAcl;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Simple MongoDB-based implementation of {@link AclService}.
 * <p>
 * This implementation differs from the SQL based implementation by having a single MongoDB collection containing all
 * the necessary ACL related data per document in a non-final structure represented by the {@link MongoAcl} POJO. This
 * service will convert database results from POJO to ACL related classes like {@link Acl}, {@link ObjectIdentity},
 * {@link Sid} and {@link AccessControlEntry} instances internally.
 *
 * @author Ben Alex
 * @author Roman Vottner
 * @since 4.3
 */
public class MongoDBAclService implements AclService {

	private static final Logger LOG = LoggerFactory.getLogger(MongoDBAclService.class);

	protected AclRepository aclRepository;

	private final LookupStrategy lookupStrategy;

	public MongoDBAclService(AclRepository aclRepository, LookupStrategy lookupStrategy) {
		Assert.notNull(aclRepository, "AclRepository required");
		Assert.notNull(lookupStrategy, "LookupStrategy required");
		this.aclRepository = aclRepository;
		this.lookupStrategy = lookupStrategy;
	}

	@Override
	public List<ObjectIdentity> findChildren(ObjectIdentity parentIdentity) {

		List<MongoAcl> aclsForDomainObject =
				aclRepository.findByInstanceIdAndClassName(parentIdentity.getIdentifier(), parentIdentity.getType());
		if (null == aclsForDomainObject || aclsForDomainObject.isEmpty()) {
			return null;
		}
		LinkedHashSet<MongoAcl> children = new LinkedHashSet<>();
		// find children for each found ACL entity
		for (MongoAcl acl : aclsForDomainObject) {
			List<MongoAcl> childAclsOfDomainObject = aclRepository.findByParentId(acl.getId());
			children.addAll(childAclsOfDomainObject);
		}

		List<ObjectIdentity> foundChildren = new ArrayList<>();
		for (MongoAcl child : children) {
			try {
				ObjectIdentity oId = new ObjectIdentityImpl(Class.forName(child.getClassName()), child.getInstanceId());
				if (!foundChildren.contains(oId)) {
					foundChildren.add(oId);
				}
			} catch (ClassNotFoundException cnfEx) {
				LOG.error("Could not find class of domain object '{}' referenced by ACL {}",
						child.getClassName(), child.getId());
			}
		}
		return foundChildren;
	}

	@Override
	public Acl readAclById(ObjectIdentity object) throws NotFoundException {
		return readAclById(object, null);
	}

	@Override
	public Acl readAclById(ObjectIdentity object, List<Sid> sids) throws NotFoundException {
		Map<ObjectIdentity, Acl> map = readAclsById(Collections.singletonList(object), sids);
		Assert.isTrue(map.containsKey(object),
				"There should have been an Acl entry for ObjectIdentity " + object);

		return map.get(object);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects)
			throws NotFoundException {
		return readAclsById(objects, null);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids)
			throws NotFoundException {
		Map<ObjectIdentity, Acl> result = lookupStrategy.readAclsById(objects, sids);

		// Check every requested object identity was found (throw NotFoundException if needed)
		for (ObjectIdentity oid : objects) {
			if (!result.containsKey(oid)) {
				throw new NotFoundException(
						"Unable to find ACL information for object identity '" + oid + "'");
			}
		}

		return result;
	}
}
