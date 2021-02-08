# Spring Security ACL MongoDB

Spring Security Access Control List (ACL) is a convenient way to grant user-based permission access on domain objects like i.e. a list of books or contacts. Spring Security by default manages ACL via 4 SQL tables which are joined together at lookup time per access on a domain object. While it makes use of caching internally to reduce the roundtrip to the database as much as possible, storing the data in a NoSQL database in a non-flat structure can further help reduce the overall overhead on the database.

This Spring Security ACL customization uses MongoDB as a database to look up access control permissions for users on a domain object by maintaining a single ACL document collection. An exemplary ACL permission entry in the collections does look like the sample code below:

```
{
    "_id" : "a285005a-a892-409a-be86-59877142aa17",
    "_class" : "org.springframework.security.acls.domain.MongoAcl",
    "className" : "sample.contact.Contact",
    "instanceId" : 6,
    "owner" : {
        "name": "rod",
        "isPrincipal": true
    },
    "inheritPermissions" : true,
    "permissions" : [ 
        {
            "_id" : "dbf4dcb0-70f4-48a5-92b0-d4c782af7498",
            "sid" : {
                "name": "dianne",
                "isPrincipal": true
            },
            "permission" : 1,
            "granting" : true,
            "auditFailure" : false,
            "auditSuccess" : false
        }, 
        {
            "_id" : "a91b1f25-9c09-4092-a82b-9f773a777f1d",
            "sid" : {
                "name": "dianne",
                "isPrincipal": true
            },
            "permission" : 2,
            "granting" : true,
            "auditFailure" : false,
            "auditSuccess" : false
        }, 
        {
            "_id" : "36443e66-2917-4c0e-a04c-405205a9b8d8",
            "sid" : {
                "name": "dianne",
                "isPrincipal": true
            },
            "permission" : 8,
            "granting" : true,
            "auditFailure" : false,
            "auditSuccess" : false
        }, 
        {
            "_id" : "758e2530-8ef6-4974-bf2a-2bd54955805b",
            "sid" : {
                "name": "scott",
                "isPrincipal": true
            },
            "permission" : 1,
            "granting" : true,
            "auditFailure" : false,
            "auditSuccess" : false
        }
    ]
}
```

`className` and `instanceId` identify the class and the actual instance of the domain object the ACL permission was created for and represent the `ObjectIdentity` in the Spring Security ACL world. The owner represents the principal name of the user who created the ACL for the respective domain object and relates to the `PrincipalSid` object used in the SQL based ACL implementation. `AccessControlEntry` entries are covered in the permissions array an define user permissions on the domain access referenced by the encapsulating ACL entry.

This implementation will read (or write) such documents as `MongoAcl` objects from (and to) the MongoDB and map the POJO to respective Spring Security ACL classes such as `Acl`, `Sid`, `ObjectIdentity` and/or `AccessControlEntry` instances. As the customized `AclService`/`MutableAclService` returns `Acl` instances replacing the SQL based ACL with the MongoDB based ACL code should be trivial.

## Installation

### Maven

This package is not on any remote repository, so the build and install of the package is needed: `mvn clean install`

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-acl-mongodb</artifactId>
    <version>5.3.6-SNAPSHOT</version>
</dependency>
```

### Gradle

```groovy
compile "org.springframework.security:spring-security-acl-mongodb:5.3.6-SNAPSHOT"
```

## Configuration

Tell your application to read the beans:

```java
@SpringBootApplication(scanBasePackages = {"com.your.app", "org.springframework.security.acls"})
```

> Been looking to autoconfigure the package without this without luck, help needed :smiley_face:

## Usage

AS this implementation maps the MongoDB documents to `AclImpl` instances used by Spring Security ACL, evaluating user permissions on accessing domain objects should be straight forward via standard `@PreAuthorize`, `@PostAuthorize`, `@PreFilter` and `@PostFilter` Spring Security annotations which get evaluated by `AclPermissionEvaluator` by default.

As `AclPermissionEvaluator` will create a `ObjectIdentityImpl` object internally for the domain object to check permissions for, the domain object itself has to contain a public accessible `getId()` method which returns a unique identifier of the domain object.

```java
public interface ContactManager {
    // ~ Methods
    // ========================================================================================================
    @PreAuthorize("hasPermission(#contact, admin)")
    void addPermission(Contact contact, Sid recipient, Permission permission);

    @PreAuthorize("hasPermission(#contact, admin)")
    void deletePermission(Contact contact, Sid recipient, Permission permission);

    @PreAuthorize("hasRole('ROLE_USER')")
    void create(Contact contact);

    @PreAuthorize("hasPermission(#contact, 'delete') or hasPermission(#contact, admin)")
    void delete(Contact contact);

    @PreAuthorize("hasRole('ROLE_USER')")
    @PostFilter("hasPermission(filterObject, 'read') or hasPermission(filterObject, admin)")
    List<Contact> getAll();

    @PreAuthorize("hasRole('ROLE_USER')")
    List<String> getAllRecipients();

    @PreAuthorize("hasPermission(#id, 'sample.contact.Contact', read) or " +
                  "hasPermission(#id, 'sample.contact.Contact', admin)")
    Contact getById(Long id);

    Contact getRandomContact();
}
```