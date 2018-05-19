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

/**
 * Represents a security identity assignable to certain permissions in an access control list. The identity can either
 * be a user principal or a granted authority. If {@link #isPrincipal} returns true, the security identity represents an
 * authenticated user, otherwise an instance of this class will represent a granted authority.
 *
 * @author Roman Vottner
 * @since 4.3
 */
public class MongoSid {
	/**
	 * The name of the security identity
	 **/
	private String name;
	/**
	 * Defines whether this security identity is a user principal (true) or a granted authority (false)
	 **/
	private boolean isPrincipal;

	/**
	 * Default constructor needed by Spring.
	 */
	public MongoSid() {

	}

	/**
	 * Creates a new security identity which represents a user principal assignable to permissions in an access control
	 * list.
	 *
	 * @param name The name of the user principal this security identity is created for
	 */
	public MongoSid(String name) {
		this.name = name;
		this.isPrincipal = true;
	}

	/**
	 * Creates a new security identity assignable to permissions in an access control list. This constructor differs
	 * from {@link #MongoSid(String)} by allowing to specify the actual type of security identity to create.
	 *
	 * @param name        The name of the user or role this security identity is created for
	 * @param isPrincipal Defines whether this security identity represents a user principal (true) or a granted
	 *                    authority (false)
	 */
	public MongoSid(String name, boolean isPrincipal) {
		this.name = name;
		this.isPrincipal = isPrincipal;
	}

	/**
	 * Returns the name of the security identity. In case {@link #isPrincipal} returns true, this is the user name,
	 * otherwise it will match the role name of the granted authority.
	 *
	 * @return The name of the security identity
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * Defines the new name of this security identity instance.
	 *
	 * @param name The name to assign to the security identity.
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Defines whether this security identity is a user principal (true) or a granted authority (false).
	 *
	 * @return <em>true</em> in case this instance represents a user principal, <em>false</em> for granted authorities
	 */
	public boolean isPrincipal() {
		return this.isPrincipal;
	}

	/**
	 * Specifies whether this instance is a user principal or a granted authority.
	 *
	 * @param isPrincipal If set to <em>true</em> will mark this security identity instance as a user principal. On
	 *                    providing <em>false</em> this instance will represent a granted authority
	 */
	public void setPrincipal(boolean isPrincipal) {
		this.isPrincipal = isPrincipal;
	}

	@Override
	public String toString() {
		return "MongoSid[name = " + name + ", isPrincipal = " + isPrincipal + "]";
	}
}
