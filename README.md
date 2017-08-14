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

# Configuration

Before being able to use Spring Security ACL MongoDB it has to be defined as dependency and configured properly in order to work.

## Dependency Management 

### Maven

In order to make use of the MongoDB based ACL one has to declare its dependency in Maven like below:

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-acl-mongodb</artifactId>
    <version>4.2.3-SNAPSHOT</version>
</dependency>
```

Note that the artifacts are not yet available on Maven Central. So please build the project manually via `mvn clean install` first before declaring the dependencies on this artifact.

### Gradle

Via Gradle the dependency can be added by simply adding the following line to the .gradle file:

```groovy
compile "org.springframework.security:spring-security-acl-mongodb:4.2.3-SNAPSHOT"
```

Note that the artifacts are not yet available on Maven Central (or similar repositories). Hence build the project manually first before declaring the dependencies on this artifact.

### XML based configuration

After the dependencies are available one must define a `MongoTemplate` as well as `MongoRepository` bean via Spring.

On using XML based configuration a sample configuration can look like below

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:mongo="http://www.springframework.org/schema/data/mongo"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="
       http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
       http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd
       http://www.springframework.org/schema/data/mongo http://www.springframework.org/schema/data/mongo/spring-mongo.xsd
       ">

    <!-- MongoDB used for the ACL management -->

    <!-- declaring a mongo client that way did not work on my site hence the manual configuration below -->
    <!--<mongo:mongo id="mongo" host="localhost" port="27017"/>-->
    <!--<mongo:db-factory id="mongoDbFactory" dbname="spring-security-acl-test" mongo-ref="mongo"/>-->

    <bean id="mongo" class="com.mongodb.MongoClient">
        <constructor-arg name="host" value="localhost"/>
        <constructor-arg name="port" value="27017"/>
    </bean>

    <bean id="mongoDbFactory" class="org.springframework.data.mongodb.core.SimpleMongoDbFactory">
        <constructor-arg name="mongoClient" ref="mongo"/>
        <constructor-arg name="databaseName" value="spring-security-acl"/>
    </bean>

    <bean id="mongoTemplate" class="org.springframework.data.mongodb.core.MongoTemplate">
        <constructor-arg ref="mongoDbFactory" />
    </bean>

    <!-- Handle MongoExceptions caught in @Repository annotated classes -->
    <bean class="org.springframework.dao.annotation.PersistenceExceptionTranslationPostProcessor"/>

    <!-- Make the aclRepository bean instance available to inject -->
    <context:annotation-config />
    <context:component-scan base-package="org.springframework.security.acls" />

    <!-- The Spring-Data-MongoDB Acl repository -->
    <mongo:repositories base-package="org.springframework.security.acls.dao"/>
</beans>
```

The database name is optional. In contrast to the SQL ACL implementation no predefined table definitions are necessary.

Once the Mongo client is available and the template as well as the repository are in place the `AclService` implementation has to be configured. The `MongoDBMutableAclService` implementation provides, in contrast to the `MongoDBAclService` implementation, which supports ACL entry lookups, full CRUD functionality on ACL entries.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

  <!-- ========= ACL SERVICE  DEFINITIONS ========= -->

  <bean id="aclCache" class="org.springframework.security.acls.domain.EhCacheBasedAclCache">
	<constructor-arg>
	  <bean class="org.springframework.cache.ehcache.EhCacheFactoryBean">
		<property name="cacheManager">
		  <bean class="org.springframework.cache.ehcache.EhCacheManagerFactoryBean"/>
		</property>
		<property name="cacheName" value="aclCache"/>
	  </bean>
	</constructor-arg>
	<constructor-arg>
		<bean class="org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy">
			<constructor-arg>
				<bean class="org.springframework.security.acls.domain.ConsoleAuditLogger"/>
			</constructor-arg>
		</bean>
	</constructor-arg>
	<constructor-arg>
		<bean class="org.springframework.security.acls.domain.AclAuthorizationStrategyImpl">
			<constructor-arg>
				<list>
					<bean class="org.springframework.security.core.authority.SimpleGrantedAuthority">
						<constructor-arg value="ROLE_ACL_ADMIN"/>
					</bean>
				</list>
			</constructor-arg>
		</bean>
	</constructor-arg>
  </bean>

  <bean id="lookupStrategy" class="org.springframework.security.acls.mongodb.BasicLookupStrategy">
	<constructor-arg ref="mongoTemplate"/>
	<constructor-arg ref="aclCache"/>
	<constructor-arg>
		<bean class="org.springframework.security.acls.domain.AclAuthorizationStrategyImpl">
			<constructor-arg>
				<bean class="org.springframework.security.core.authority.SimpleGrantedAuthority">
					<constructor-arg value="ROLE_ADMINISTRATOR"/>
				</bean>
			</constructor-arg>
		</bean>
	</constructor-arg>
	<constructor-arg>
	  <bean class="org.springframework.security.acls.domain.ConsoleAuditLogger"/>
	</constructor-arg>
  </bean>

  <bean id="aclService" class="org.springframework.security.acls.mongodb.MongoDBMutableAclService">
	<constructor-arg ref="lookupStrategy"/>
	<constructor-arg ref="aclCache"/>
  </bean>

</beans>
```

The `aclService` can then be used to inject an instance into some business logic classes as depicted below:

```xml
    <!-- The business class implementing the actual logic -->

    <bean id="contactManager" class="sample.contact.ContactManagerBackend">
        <property name="contactDao">
            <bean class="sample.contact.ContactDaoSpring">
                <property name="dataSource" ref="dataSource"/>
            </bean>
        </property>
        <property name="mutableAclService" ref="aclService"/>
    </bean>
```

### Java based configuration

The configuration via Java configuration isn't that differnt from the XML based configuration. 

```java
@Configuration
@EnableMongoRepositories(basePackageClasses = {AclRepository.class })
public class ContextConfig {

    @Bean
    public MongoTemplate mongoTemplate() throws UnknownHostException
    {
        MongoClient mongoClient = new MongoClient("localhost", 27017);
        return new MongoTemplate(mongoClient, "spring-security-acl-test");
    }

    @Bean
    public AclAuthorizationStrategy aclAuthorizationStrategy() {
        return new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_ADMINISTRATOR"));
    }

    @Bean
    public PermissionGrantingStrategy permissionGrantingStrategy() {
        ConsoleAuditLogger consoleAuditLogger = new ConsoleAuditLogger();
        return new DefaultPermissionGrantingStrategy(consoleAuditLogger);
    }

    @Bean
    public LookupStrategy lookupStrategy() throws UnknownHostException {
        return new BasicLookupStrategy(mongoTemplate(), aclCache(), aclAuthorizationStrategy(), permissionGrantingStrategy());
    }

    @Bean
    public CacheManager cacheManager() {
        return new ConcurrentMapCacheManager("test");
    }

    @Bean
    public AclCache aclCache() {
        Cache springCache = cacheManager().getCache("test");
        return new SpringCacheBasedAclCache(springCache, permissionGrantingStrategy(), aclAuthorizationStrategy());
    }

    @Bean
    public AclService aclService() throws UnknownHostException {
        return new MongoDBMutableAclService(lookupStrategy(), aclCache());
    }
}
```

As usual both `AclRepository` and `MongoDBMutableAclService` can be injected using either `@Autowired`, `@Resource` or `@Inject` annotations

```java
@Resource
private MongoDBMutableAclService aclService;
@Resource
private AclRepository aclRepository;
```

# Usage

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