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

import java.util.UUID;

/**
 * Simple domain object used for testing ACLs.
 *
 * @author Roman Vottner
 * @since 4.3
 */
class TestDomainObject {

	private final String id = UUID.randomUUID().toString();

	/**
	 * Returns the unique ID in the form of a UUID v4.
	 *
	 * @return the unique ID of this object
	 */
	String getId() {
		return this.id;
	}
}
