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
package org.springframework.security.acls.domain;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents an access control list configuration for a domain object specified by its unique identifier. An instance
 * of this class defines an owner of a domain object, a parent ACL configuration instance, which it may inherit
 * permissions from, as well as a list of user permissions for the referenced domain object.
 * <p>
 * This class is a mapping class for {@link Acl} instances which should be persisted to a MongoDB database.
 *
 * @author Roman Vottner
 * @since 4.3
 */
@CompoundIndexes({
		@CompoundIndex(name = "domainObject", def = "{'instanceId' : 1, 'className' : 1}")
})
@Document(collection = "ACL")
public class MongoAcl {
	/**
	 * The unique identifier of the ACL pointing to some domain object
	 **/
	@Id
	private Serializable id;
	/**
	 * The fully qualified class name of the domain object
	 **/
	private String className;
	/**
	 * A reference to the unique identifier of the domain object this ACL was created for
	 **/
	private Serializable instanceId;
	/**
	 * The unique identifier of the user owning the domain object
	 **/
	private MongoSid owner;
	/**
	 * A reference to a parent ACL which may inherit permissions. Can be null
	 **/
	@Indexed
	private Serializable parentId = null;
	/**
	 * Defines whether to inherit permissions from parent ACL or not. If set to true permissions will be inherited from
	 * parent ACLs
	 **/
	private boolean inheritPermissions = true;
	/**
	 * A list containing access control permissions per user on the domain object this ACL references to
	 **/
	private List<DomainObjectPermission> permissions = new ArrayList<>();

	public MongoAcl() {

	}

	/**
	 * Creates a new access control list instance for a domain object identified by the given <em>instanceId</em> unique
	 * identifier. The class of the domain object is identified via the provided <em>className</em> argument. This
	 * constructor will set the currently authenticated user as the owner of the domain object identified by the passed
	 * <em>instanceId</em>.
	 *
	 * @param instanceId The unique identifier of the domain object a new access control list should be generated for
	 * @param className  The fully qualified class name of the domain object
	 * @param id         The unique identifier of this access control list
	 */
	public MongoAcl(Serializable instanceId, String className, Serializable id) {
		this.id = id;
		this.instanceId = instanceId;
		this.className = className;
		// assign the user who created the object as owner

		String ownerName = SecurityContextHolder.getContext().getAuthentication().getName();
		this.owner = new MongoSid(ownerName);
	}

	/**
	 * Creates a new access control list instance for a domain object identified by the given <em>instanceId</em> unique
	 * identifier. The class of the domain object is identified via the provided <em>className</em> argument.
	 *
	 * @param instanceId        The unique identifier of the domain object a new access control list should be generated
	 *                          for
	 * @param className         The fully qualified class name of the domain object
	 * @param id                The unique identifier of this access control list
	 * @param owner             The owner of the domain object. Note an owner has full access to the domain object
	 * @param parentId          A unique identifier to a parent access control list which contains permissions which are
	 *                          inherited if <em>entriesInheriting</em> argument is set to true
	 * @param entriesInheriting If set to true will include checking permissions from ancestor access control list
	 *                          entries
	 */
	public MongoAcl(Serializable instanceId, String className, Serializable id, MongoSid owner,
					Serializable parentId, boolean entriesInheriting) {
		this(instanceId, className, id);
		this.parentId = parentId;
		this.owner = owner;
		this.inheritPermissions = entriesInheriting;
	}

	/**
	 * Returns the name of the domain object class this ACL is referring to .
	 *
	 * @return The class name of the referenced domain object
	 */
	public String getClassName() {
		return this.className;
	}

	/**
	 * Returns the unique identifier of the domain object referenced by this ACL.
	 *
	 * @return The unique identifier of the domain object
	 */
	public Serializable getInstanceId() {
		return this.instanceId;
	}

	/**
	 * Returns the owner this ACL defines on the domain object.
	 *
	 * @return The owner of the domain object
	 */
	public MongoSid getOwner() {
		return this.owner;
	}

	/**
	 * Returns the unique identifier of this ACL instance.
	 *
	 * @return The unique identifier of this ACL
	 */
	public Serializable getId() {
		return this.id;
	}

	/**
	 * Defines if ancestor permissions should be taken into account when evaluating access permissions on the domain
	 * object.
	 *
	 * @return <em>true</em> if permissions from ancestor ACLs are evaluated on accessing the domain object;
	 * <em>false</em> otherwise
	 */
	public boolean isInheritPermissions() {
		return this.inheritPermissions;
	}

	/**
	 * Returns the unique identifier of the parent ACL instance if specified.
	 *
	 * @return The unique identifier of the parent ACL or null if no parent was specified
	 */
	public Serializable getParentId() {
		return this.parentId;
	}

	/**
	 * Returns the permissions on the domain object monitored by this ACL instance.
	 *
	 * @return A list of user permissions on the domain object monitored by this ACL
	 */
	public List<DomainObjectPermission> getPermissions() {
		return this.permissions;
	}

	/**
	 * Specifies the unique identifier of the parent ACL.
	 *
	 * @param parentId The unique identifier of the parent ACL
	 */
	public void setParentId(String parentId) {
		this.parentId = parentId;
	}

	/**
	 * Specifies the user permissions on the domain object monitored by this ACL instance.
	 *
	 * @param permissions The user permissions on the domain object
	 */
	public void setPermissions(List<DomainObjectPermission> permissions) {
		this.permissions = permissions;
	}

	/**
	 * Specifies whether parent access permisssions should be taken into account when evaluating user access permissions
	 * on a domain object.
	 *
	 * @param inheritPermissions <em>true</em> if parent permissions should be evaluated on user access of the domain
	 *                           object; <em>false</em> if only the permissions by this ACL should be reconsidered on
	 *                           evaluating access permissions
	 */
	public void setInheritPermissions(boolean inheritPermissions) {
		this.inheritPermissions = inheritPermissions;
	}

	@Override
	public String toString() {
		return "MongoAcl[id = " + id
				+ ", className = " + className
				+ ", instanceId = " + instanceId
				+ ", parentId = " + parentId
				+ ", inheritPermissions = " + inheritPermissions
				+ ", owner = " + owner
				+ ", permissions = " + permissions
				+ "]";
	}
}
