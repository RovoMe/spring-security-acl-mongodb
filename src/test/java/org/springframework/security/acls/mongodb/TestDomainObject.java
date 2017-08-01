package org.springframework.security.acls.mongodb;

import java.util.UUID;

public class TestDomainObject
{
    private final String id = UUID.randomUUID().toString();

    public String getId() {
        return this.id;
    }
}
