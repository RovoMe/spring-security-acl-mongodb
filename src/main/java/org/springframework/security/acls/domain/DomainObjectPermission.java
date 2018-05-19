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

import org.springframework.util.Assert;

import java.io.Serializable;

/**
 * Represents a permission setting per user for a domain object referenced by the {@link MongoAcl} instance which
 * holds instances of this class.
 * <p>
 * This class is a mapping class for {@link org.springframework.security.acls.model.AccessControlEntry} instances which
 * are persisted into a MongoDB database. Instead of keeping the data separated into different collections, similar to
 * the SQL approach, permissions are embedded into the Mongo ACL entry. This is necessary as MongoDB does not support
 * table joins, like SQL does, and also keeps data that belong to each other within the same collection entry to avoid
 * lookup time.
 *
 * @author Roman Vottner
 * @since 4.3
 */
public class DomainObjectPermission {
	/**
	 * The unique identifier of this permission instance
	 **/
	private final Serializable id;
	/**
	 * The security identity the permission is created for
	 **/
	private final MongoSid sid;
	/**
	 * A bit-mask containing the relevant access permission for the user referenced by {@link #sid}.
	 **/
	private int permission;
	/**
	 * Defines whether this permission is specifying granting permissions or denying permissions to a domain object. In
	 * case this field is set to false a write permission defined in {@link #permission} will read like deny writes by
	 * the user identified by the <em>sid</em> for the respective domain object
	 **/
	private final boolean granting;
	/**
	 * Defines whether denied access to certain resources should be logged or not. If set to true any security related
	 * issues will be logged
	 **/
	private boolean auditFailure;
	/**
	 * Defines whether successful access to certain resources should be logged. If set to true any successful access
	 * will be logged
	 */
	private boolean auditSuccess;

	/**
	 * Creates a new permission for a given user identified by its unique identifier passed in as <em>sid</em> parameter.
	 * The actual access permission for domain object are encapsulated by a bit-mask provided as <em>permission</em>
	 * argument.
	 * <p>
	 * Note that although a permission for a user is created for a certain domain object, this permission entry is added
	 * to the permissions list on the ACL for the respective domain object and hence no reference to the actual domain
	 * object or the ACL are stored within an instance of this class.
	 *
	 * @param id           The unique identifier of this permission entry
	 * @param sid          The security identity the permission is created for
	 * @param permission   A bit-mask defining the actual permission the user identified by the given <em>sid</em>
	 *                     argument has on a certain domain object
	 * @param granting     Defines if permissions passed are for granting or denying purposes. If this argument is set
	 *                     to false any permissions provided will be for deny cases
	 * @param auditSuccess Defines if successful access attempts on the domain object by this user should be logged
	 * @param auditFailure Defines if failed access attempts on the domain object by this user should be logged
	 */
	public DomainObjectPermission(Serializable id, MongoSid sid, int permission,
								  boolean granting, boolean auditSuccess, boolean auditFailure) {
		Assert.notNull(sid, "Sid required");
		this.id = id;
		this.sid = sid;
		this.permission = permission;
		this.granting = granting;
		this.auditSuccess = auditSuccess;
		this.auditFailure = auditFailure;
	}

	/**
	 * Returns the unique identifier of this user permission entry.
	 *
	 * @return The unique identifier of this permission entry
	 */
	public Serializable getId() {
		return this.id;
	}

	/**
	 * Returns the permissions of the user identified by {@link #sid} as bit mask.
	 *
	 * @return The user access permissions as bit mask
	 */
	public int getPermission() {
		return this.permission;
	}

	/**
	 * Returns the security identity this permission entry was created for.
	 *
	 * @return The user this permission is for
	 */
	public MongoSid getSid() {
		return this.sid;
	}

	/**
	 * Defines whether a failed access on a domain object by this user should be logged.
	 *
	 * @return <em>true</em> if failed domain object access should be logged; <em>false</em> otherwise
	 */
	public boolean isAuditFailure() {
		return this.auditFailure;
	}

	/**
	 * Defines whether successful domain object access by this user should be logged.
	 *
	 * @return <em>true</em> if successful domain object access should be logged; <em>false</em> otherwise
	 */
	public boolean isAuditSuccess() {
		return this.auditSuccess;
	}

	/**
	 * Specifies whether the permissions returned by {@link #getPermission()} are for a granting or rejecting purpose.
	 *
	 * @return <em>true</em> if permissions returned by {@link #getPermission()} specify granting permissions;
	 * <em>false</em> will state that permissions returned by {@link #getPermission()} are for rejecting a user on a
	 * match.
	 */
	public boolean isGranting() {
		return this.granting;
	}

	/**
	 * Specifies whether failed domain object access should be logged.
	 *
	 * @param auditFailure <em>true</em> if failed domain object access should be looged; <em>false</em> otherwise
	 */
	public void setAuditFailure(boolean auditFailure) {
		this.auditFailure = auditFailure;
	}

	/**
	 * Specifies whether successful domain object access should be logged.
	 *
	 * @param auditSuccess <em>true</em> if successful domain object access should be looged; <em>false</em> otherwise
	 */
	public void setAuditSuccess(boolean auditSuccess) {
		this.auditSuccess = auditSuccess;
	}

	/**
	 * Specifies the access permission for the user returned by {@link #getSid()} on a domain object held by the ACL
	 * that holds this permission entry.
	 * <p>
	 * Access control permissions can be chained together using the bit-operator <em>|</em> like in the sample below
	 * which defines read and write access for a certain user:
	 * <pre>{@code BasePermission.READ.getMask() | BasePermission.WRITE.getMask()}</pre>
	 *
	 * @param permission The permission set for a certain user
	 */
	public void setPermission(int permission) {
		this.permission = permission;
	}

	@Override
	public String toString() {
		return "DomainObjectPermission[id = " + id
				+ ", sid = " + sid
				+ ", permission = " + permission
				+ ", granting = " + granting
				+ ", auditSuccess = " + auditSuccess
				+ ", auditFailure = " + auditFailure
				+ "]";
	}
}
