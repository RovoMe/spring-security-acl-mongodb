package org.springframework.security.acls.mongodb;

import com.mongodb.MongoClient;
import java.net.UnknownHostException;
import java.util.List;
import java.util.UUID;
import javax.annotation.Resource;
import org.junit.After;
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
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { MongoDBMutableAclServiceTest.ContextConfig.class },
        loader = AnnotationConfigContextLoader.class)
@TestExecutionListeners(listeners = { MongoDBTestExecutionListener.class },
        mergeMode = TestExecutionListeners.MergeMode.MERGE_WITH_DEFAULTS)
public class MongoDBMutableAclServiceTest {

    @Configuration
    @EnableMongoRepositories(basePackageClasses = {AclRepository.class })
    public static class ContextConfig {

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

    @Resource
    private MongoDBMutableAclService aclService;
    @Resource
    private AclRepository aclRepository;

    @After
    public void cleanup() {
        aclRepository.delete(aclRepository.findAll());
    }

    @Test
    @WithMockUser
    public void testCreateAcl() throws Exception {
        // Arrange
        TestDomainObject domainObject = new TestDomainObject();

        // Act
        ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());
        Acl acl = aclService.createAcl(objectIdentity);

        // Assert
        assertThat(acl, is(notNullValue()));
        assertThat(acl.getObjectIdentity().getIdentifier(), is(equalTo(domainObject.getId())));
        assertThat(acl.getObjectIdentity().getType(), is(equalTo(domainObject.getClass().getName())));
        assertThat(acl.getOwner(), is(equalTo(new PrincipalSid(SecurityContextHolder.getContext().getAuthentication().getName()))));
    }

    @Test
    @WithMockUser
    public void testDeleteAcl() throws Exception {
        // Arrange
        TestDomainObject domainObject = new TestDomainObject();
        ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

        MongoAcl mongoAcl = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(),
                                         UUID.randomUUID().toString(), SecurityContextHolder.getContext().getAuthentication().getName(),
                                         null, true);
        DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
                                                                       SecurityContextHolder.getContext().getAuthentication().getName(),
                                                                       BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
                                                                       true, true, true);
        mongoAcl.getPermissions().add(permission);

        aclRepository.save(mongoAcl);

        // Act
        aclService.deleteAcl(objectIdentity, true);

        // Assert
        MongoAcl afterDelete = aclRepository.findById(mongoAcl.getId());
        assertThat(afterDelete, is(nullValue()));
    }

    @Test
    @WithMockUser
    public void testDeleteAcl_includingChildren() throws Exception {
        // Arrange
        TestDomainObject domainObject = new TestDomainObject();
        TestDomainObject firstObject = new TestDomainObject();
        TestDomainObject secondObject = new TestDomainObject();
        TestDomainObject thirdObject = new TestDomainObject();
        TestDomainObject unrelatedObject = new TestDomainObject();

        ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

        MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString());
        MongoAcl child1 = new MongoAcl(firstObject.getId(), firstObject.getClass().getName(), UUID.randomUUID().toString(), "Tim Test", parent.getId(), true);
        MongoAcl child2 = new MongoAcl(secondObject.getId(), secondObject.getClass().getName(), UUID.randomUUID().toString(), "Petty Pattern", parent.getId(), true);
        MongoAcl child3 = new MongoAcl(thirdObject.getId(), thirdObject.getClass().getName(), UUID.randomUUID().toString(), "Sam Sample", parent.getId(), true);
        MongoAcl nonChild = new MongoAcl(unrelatedObject.getId(), unrelatedObject.getClass().getName(), UUID.randomUUID().toString());

        DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
                                                                       SecurityContextHolder.getContext().getAuthentication().getName(),
                                                                       BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
                                                                       true, true, true);

        parent.getPermissions().add(permission);
        child1.getPermissions().add(permission);
        child2.getPermissions().add(permission);

        aclRepository.save(parent);
        aclRepository.save(child1);
        aclRepository.save(child2);
        aclRepository.save(child3);
        aclRepository.save(nonChild);

        // Act
        aclService.deleteAcl(objectIdentity, true);

        // Assert
        MongoAcl afterDelete = aclRepository.findById(parent.getId());
        assertThat(afterDelete, is(nullValue()));
        List<MongoAcl> remaining = aclRepository.findAll();
        assertThat(remaining.size(), is(equalTo(1)));
        assertThat(remaining.get(0).getId(), is(equalTo(nonChild.getId())));
    }

    @Test
    @WithMockUser
    public void testDeleteAcl_excludingChildren() throws Exception {
        // Arrange
        TestDomainObject domainObject = new TestDomainObject();
        TestDomainObject firstObject = new TestDomainObject();
        TestDomainObject secondObject = new TestDomainObject();
        TestDomainObject thirdObject = new TestDomainObject();
        TestDomainObject unrelatedObject = new TestDomainObject();

        ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

        MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString());
        MongoAcl child1 = new MongoAcl(firstObject.getId(), firstObject.getClass().getName(), UUID.randomUUID().toString(), "Tim Test", parent.getId(), true);
        MongoAcl child2 = new MongoAcl(secondObject.getId(), secondObject.getClass().getName(), UUID.randomUUID().toString(), "Petty Pattern", parent.getId(), true);
        MongoAcl child3 = new MongoAcl(thirdObject.getId(), thirdObject.getClass().getName(), UUID.randomUUID().toString(), "Sam Sample", parent.getId(), true);
        MongoAcl nonChild = new MongoAcl(unrelatedObject.getId(), unrelatedObject.getClass().getName(), UUID.randomUUID().toString());

        DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
                                                                       SecurityContextHolder.getContext().getAuthentication().getName(),
                                                                       BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
                                                                       true, true, true);

        parent.getPermissions().add(permission);
        child1.getPermissions().add(permission);
        child2.getPermissions().add(permission);

        aclRepository.save(parent);
        aclRepository.save(child1);
        aclRepository.save(child2);
        aclRepository.save(child3);
        aclRepository.save(nonChild);

        // Act
        try {
            aclService.deleteAcl(objectIdentity, false);
            fail("Should have thrown an exception as removing a parent ACL is not allowed");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ChildrenExistException.class));
        }
    }

    @Test
    @WithMockUser
    public void testUpdateAcl() throws Exception {
        // Arrange
        TestDomainObject domainObject = new TestDomainObject();
        ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

        MongoAcl mongoAcl = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(),
                                         UUID.randomUUID().toString(), SecurityContextHolder.getContext().getAuthentication().getName(),
                                         null, true);
        DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
                                                                       SecurityContextHolder.getContext().getAuthentication().getName(),
                                                                       BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
                                                                       true, true, true);
        mongoAcl.getPermissions().add(permission);
        aclRepository.save(mongoAcl);

        MutableAcl updatedAcl = (MutableAcl)aclService.readAclById(objectIdentity);
        updatedAcl.insertAce(updatedAcl.getEntries().size(), BasePermission.ADMINISTRATION, new PrincipalSid("Sam Sample"), true);

        // Act
        aclService.updateAcl(updatedAcl);

        // Assert
        MongoAcl updated = aclRepository.findById(mongoAcl.getId());
        assertThat(updated.getPermissions().size(), is(equalTo(2)));
        assertThat(updated.getPermissions().get(0).getId(), is(equalTo(permission.getId())));
        assertThat(updated.getPermissions().get(1).getPermission(), is(equalTo(BasePermission.ADMINISTRATION.getMask())));
        assertThat(updated.getPermissions().get(1).getSid(), is(equalTo("Sam Sample")));
    }
}
