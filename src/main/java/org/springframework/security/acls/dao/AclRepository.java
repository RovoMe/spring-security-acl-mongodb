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
package org.springframework.security.acls.dao;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.security.acls.domain.MongoAcl;
import org.springframework.stereotype.Repository;

import java.io.Serializable;
import java.util.List;
import java.util.Optional;

/**
 * Spring Data MongoDB aclRepository for {@link MongoAcl} instances.
 *
 * @author Roman Vottner
 * @since 4.3
 */
@Repository
public interface AclRepository extends MongoRepository<MongoAcl, Serializable> {

	/**
	 * Retrieves an access control list by its unique identifier.
	 *
	 * @param id The unique identifier of the access control list to return
	 * @return The ACL instance identified by the given ID
	 */
	Optional<MongoAcl> findById(Serializable id);

	/**
	 * Returns the ACL for a given domain object identifier and its class name.
	 *
	 * @param instanceId The unique identifier of the domain object the ACL should be returned for
	 * @param className  The class name of the domain object referenced by the ACL
	 * @return The access control list for the matching domain object.
	 */
	List<MongoAcl> findByInstanceIdAndClassName(Serializable instanceId, String className);

	/**
	 * Retrieves all child ACLs which specified the given <em>parentId</em> as their parent.
	 *
	 * @param parentId The unique identifier of the parent ACL
	 * @return A list of child ACLs for the given parent ACL ID.
	 */
	List<MongoAcl> findByParentId(Serializable parentId);

	/**
	 * Removes a document from the ACL collection that contains an instanceId field set to the provided value.
	 *
	 * @param instanceId The unique identifier of the domain object to remove an ACL entry for
	 * @return The number of deleted documents
	 */
	Long deleteByInstanceId(Serializable instanceId);
}
