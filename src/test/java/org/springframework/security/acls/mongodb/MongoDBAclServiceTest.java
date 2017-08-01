package org.springframework.security.acls.mongodb;

import com.mongodb.MongoClient;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.annotation.Resource;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.security.acls.dao.AclRepository;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.DomainObjectPermission;
import org.springframework.security.acls.domain.MongoAcl;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.domain.SpringCacheBasedAclCache;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { MongoDBAclServiceTest.ContextConfig.class },
        loader = AnnotationConfigContextLoader.class)
@TestExecutionListeners(listeners = { MongoDBTestExecutionListener.class },
        mergeMode = TestExecutionListeners.MergeMode.MERGE_WITH_DEFAULTS)
public class MongoDBAclServiceTest {

    @Configuration
    @EnableMongoRepositories(basePackageClasses = { AclRepository.class })
    public static class ContextConfig {

        @Bean
        public MongoTemplate mongoTemplate() throws UnknownHostException {
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
            return new MongoDBAclService(lookupStrategy());
        }
    }

    @Resource
    private MongoDBAclService aclService;
    @Resource
    private MongoTemplate mongoTemplate;

    /**
     * Tests the retrieval of child domain objects by providing a representation of the parent domain object holder.
     * Note the current implementation does filter duplicate children.
     */
    @Test
    public void testFindChildren() throws Exception {
        // Arrange
        TestDomainObject domainObject = new TestDomainObject();
        TestDomainObject otherDomainObject = new TestDomainObject();
        TestDomainObject unreladedDomainObject = new TestDomainObject();

        MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString());
        MongoAcl child1 = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(), "Tim Test", parent.getId(), true);
        MongoAcl child2 = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(), "Petty Pattern", parent.getId(), true);
        MongoAcl child3 = new MongoAcl(otherDomainObject.getId(), otherDomainObject.getClass().getName(), UUID.randomUUID().toString(), "Sam Sample", parent.getId(), true);
        MongoAcl nonChild = new MongoAcl(unreladedDomainObject.getId(), unreladedDomainObject.getClass().getName(), UUID.randomUUID().toString());

        mongoTemplate.save(parent);
        mongoTemplate.save(child1);
        mongoTemplate.save(child2);
        mongoTemplate.save(child3);
        mongoTemplate.save(nonChild);

        // Act
        ObjectIdentity parentIdentity = new ObjectIdentityImpl(Class.forName(parent.getClassName()), parent.getInstanceId());
        List<ObjectIdentity> children = aclService.findChildren(parentIdentity);

        // Assert
        assertThat(children.size(), is(equalTo(2)));
        assertThat(children.get(0).getIdentifier(), is(equalTo(domainObject.getId())));
        assertThat(children.get(0).getType(), is(equalTo(domainObject.getClass().getName())));
        assertThat(children.get(1).getIdentifier(), is(equalTo(otherDomainObject.getId())));
        assertThat(children.get(1).getType(), is(equalTo(otherDomainObject.getClass().getName())));
    }

    @Test
    public void testReadAclById() throws Exception {

        // Arrange
        int readWritePermissions = BasePermission.READ.getMask() | BasePermission.WRITE.getMask();
        int readWriteCreatePermissions = BasePermission.READ.getMask() | BasePermission.WRITE.getMask() | BasePermission.CREATE.getMask();

        TestDomainObject parentObject = new TestDomainObject();
        TestDomainObject domainObject = new TestDomainObject();

        MongoAcl parentAcl = new MongoAcl(parentObject.getId(), parentObject.getClass().getName(), UUID.randomUUID().toString(), "Check Norris", null, true);
        MongoAcl mongoAcl = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(), "Petty Pattern", parentAcl.getId(), true);
        List<DomainObjectPermission> permissions = new ArrayList<>();
        permissions.add(new DomainObjectPermission(UUID.randomUUID().toString(), "Sam Sample",
                                                   readWritePermissions, true, false, true));
        permissions.add(new DomainObjectPermission(UUID.randomUUID().toString(), "Tim Test",
                                                   readWriteCreatePermissions, true, false, true));
        mongoAcl.setPermissions(permissions);

        mongoTemplate.save(parentAcl);
        mongoTemplate.save(mongoAcl);

        // Act
        ObjectIdentity parentIdentity = new ObjectIdentityImpl(Class.forName(parentAcl.getClassName()), parentAcl.getInstanceId());
        ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(mongoAcl.getClassName()), mongoAcl.getInstanceId());
        Acl pAcl = aclService.readAclById(parentIdentity);
        Acl acl = aclService.readAclById(objectIdentity);

        // Assert
        assertThat(acl.getObjectIdentity().getIdentifier(), is(equalTo(domainObject.getId())));
        assertThat(acl.getObjectIdentity().getType(), is(equalTo(domainObject.getClass().getName())));
        assertThat(acl.getParentAcl(), is(equalTo(pAcl)));
        assertThat(acl.getEntries().size(), is(equalTo(2)));
        assertThat(acl.getEntries().get(0).getSid(), is(equalTo(new PrincipalSid("Sam Sample"))));
        assertThat(acl.getEntries().get(0).getPermission().getMask(), is(equalTo(readWritePermissions)));
        assertThat(acl.getOwner(), is(equalTo(new PrincipalSid("Petty Pattern"))));
        assertThat(acl.isEntriesInheriting(), is(equalTo(true)));
    }
}
