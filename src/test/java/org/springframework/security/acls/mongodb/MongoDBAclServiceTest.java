package org.springframework.security.acls.mongodb;

import com.mongodb.MongoClient;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import org.springframework.security.acls.domain.MongoSid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.domain.SpringCacheBasedAclCache;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;
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
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.hasKey;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

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
    @Resource
    private AclRepository aclRepository;

    /**
     * Tests the retrieval of child domain objects by providing a representation of the parent domain object holder.
     * Note the current implementation does filter duplicate children.
     */
    @Test
    @WithMockUser
    public void testFindChildren() throws Exception {
        // Arrange
        TestDomainObject domainObject = new TestDomainObject();
        TestDomainObject otherDomainObject = new TestDomainObject();
        TestDomainObject unreladedDomainObject = new TestDomainObject();

        MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString());
        MongoAcl child1 = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Tim Test"), parent.getId(), true);
        MongoAcl child2 = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parent.getId(), true);
        MongoAcl child3 = new MongoAcl(otherDomainObject.getId(), otherDomainObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Sam Sample"), parent.getId(), true);
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
    @WithMockUser
    public void testReadAclById() throws Exception {

        // Arrange
        int readWritePermissions = BasePermission.READ.getMask() | BasePermission.WRITE.getMask();
        int readWriteCreatePermissions = BasePermission.READ.getMask() | BasePermission.WRITE.getMask() | BasePermission.CREATE.getMask();

        TestDomainObject parentObject = new TestDomainObject();
        TestDomainObject domainObject = new TestDomainObject();

        MongoAcl parentAcl = new MongoAcl(parentObject.getId(), parentObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Check Norris"), null, true);
        MongoAcl mongoAcl = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parentAcl.getId(), true);
        List<DomainObjectPermission> permissions = new ArrayList<>();
        permissions.add(new DomainObjectPermission(UUID.randomUUID().toString(), new MongoSid("Sam Sample"),
                                                   readWritePermissions, true, false, true));
        permissions.add(new DomainObjectPermission(UUID.randomUUID().toString(), new MongoSid("Tim Test"),
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

    @Test
    @WithMockUser
    public void testReadAclsById_ForSpecifiedSids() throws Exception {

        // Arrange
        TestDomainObject domainObject = new TestDomainObject();
        TestDomainObject firstObject = new TestDomainObject();
        TestDomainObject secondObject = new TestDomainObject();
        TestDomainObject thirdObject = new TestDomainObject();
        TestDomainObject unrelatedObject = new TestDomainObject();

        MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString());
        MongoAcl child1 = new MongoAcl(firstObject.getId(), firstObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Tim Test"), parent.getId(), true);
        MongoAcl child2 = new MongoAcl(secondObject.getId(), secondObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parent.getId(), true);
        MongoAcl child3 = new MongoAcl(thirdObject.getId(), thirdObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Sam Sample"), parent.getId(), true);
        MongoAcl nonChild = new MongoAcl(unrelatedObject.getId(), unrelatedObject.getClass().getName(), UUID.randomUUID().toString());

        DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
                                                                       new MongoSid(SecurityContextHolder.getContext().getAuthentication().getName()),
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
        List<Sid> sids = new ArrayList<>();
        sids.add(new PrincipalSid("Tim Test")); // first object owner
        sids.add(new PrincipalSid("Sam Sample")); // third object owner

        ObjectIdentity parentIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());
        ObjectIdentity firstObjectIdentity = new ObjectIdentityImpl(Class.forName(firstObject.getClass().getName()), firstObject.getId());
        ObjectIdentity secondObjectIdentity = new ObjectIdentityImpl(Class.forName(secondObject.getClass().getName()), secondObject.getId());
        ObjectIdentity thirdObjectIdentity = new ObjectIdentityImpl(Class.forName(thirdObject.getClass().getName()), thirdObject.getId());

        // Quote from AclService's Javadoc:
        //     "The returned map is keyed on the passed objects, with the values being the <tt>Acl</tt> instances. Any
        //      unknown objects (or objects for which the interested <tt>Sid</tt>s do not have entries) will not have a
        //      map key."
        // The verification in AclService though throws a NotFoundException if an ACL for a given ObjectIdentity could
        // not be obtained!

        // neither the parent ...
        try {
            aclService.readAclsById(Arrays.asList(parentIdentity), sids);
            fail("Should have thrown a NotFoundException as no ACL should be obtainable as the parent ACL does not " +
                 "define permissions for any identity provided in the given list");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(NotFoundException.class));
        }
        // ... nor a sibling which do not specify any of the provided sids in the permissions (or owner) shall be
        // obtainable
        try {
            aclService.readAclsById(Arrays.asList(firstObjectIdentity, secondObjectIdentity, thirdObjectIdentity), sids);
            fail("Should have thrown a NotFoundException as no ACL should be obtainable for the second object identity " +
                 "passed in due to not specifying any of the provided security identities");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(NotFoundException.class));
        }

        Map<ObjectIdentity, Acl> acl = aclService.readAclsById(Arrays.asList(firstObjectIdentity, thirdObjectIdentity), sids);

        // Assert
        assertThat(acl, hasKey(firstObjectIdentity));
        assertThat(acl, hasKey(thirdObjectIdentity));
        assertThat(acl, not(hasKey(secondObjectIdentity)));
    }

    @Test
    @WithMockUser
    public void testReadAclsById_checkChildAclIsInheritingPermissions() throws Exception {
        // Arrange
        TestDomainObject domainObject = new TestDomainObject();
        TestDomainObject firstObject = new TestDomainObject();
        TestDomainObject secondObject = new TestDomainObject();
        TestDomainObject thirdObject = new TestDomainObject();
        TestDomainObject unrelatedObject = new TestDomainObject();

        ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

        MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString());
        MongoAcl child1 = new MongoAcl(firstObject.getId(), firstObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Tim Test"), parent.getId(), true);
        MongoAcl child2 = new MongoAcl(secondObject.getId(), secondObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parent.getId(), true);
        MongoAcl child3 = new MongoAcl(thirdObject.getId(), thirdObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Sam Sample"), parent.getId(), true);
        MongoAcl nonChild = new MongoAcl(unrelatedObject.getId(), unrelatedObject.getClass().getName(), UUID.randomUUID().toString());

        DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
                                                                       new MongoSid(SecurityContextHolder.getContext().getAuthentication().getName()),
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
        List<Sid> sids = new LinkedList<>();
        sids.add(new PrincipalSid(SecurityContextHolder.getContext().getAuthentication().getName()));
        sids.add(new PrincipalSid("Tim Test"));

        List<ObjectIdentity> childObjects = aclService.findChildren(objectIdentity);
        Map<ObjectIdentity, Acl> resultUser = aclService.readAclsById(childObjects, sids);

        // Assert
        // The default constructor on the parent ACL sets the owner to the authenticated user by default though the
        // parent also specifies permission for the current user explicitly. As permissions are looked up on ancestors
        // in case `entriesInheriting` is set to true, the 3rd child is also retrieved here as well
        assertThat(resultUser.keySet().size(), is(equalTo(3)));
    }

    @Test
    @WithMockUser
    public void testReadAclsById_checkAclContainsProperInheritanceStructure() throws Exception {
        // Arrange
        TestDomainObject domainObject = new TestDomainObject();
        TestDomainObject firstObject = new TestDomainObject();
        TestDomainObject secondObject = new TestDomainObject();
        TestDomainObject thirdObject = new TestDomainObject();
        TestDomainObject unrelatedObject = new TestDomainObject();

        ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

        MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(),new MongoSid("owner"), null, true);
        MongoAcl child1 = new MongoAcl(firstObject.getId(), firstObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Tim Test"), parent.getId(), true);
        MongoAcl child2 = new MongoAcl(secondObject.getId(), secondObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parent.getId(), true);
        MongoAcl child3 = new MongoAcl(thirdObject.getId(), thirdObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Sam Sample"), parent.getId(), true);
        MongoAcl nonChild = new MongoAcl(unrelatedObject.getId(), unrelatedObject.getClass().getName(), UUID.randomUUID().toString());

        DomainObjectPermission permission = new DomainObjectPermission(UUID.randomUUID().toString(),
                                                                       new MongoSid(SecurityContextHolder.getContext().getAuthentication().getName()),
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
        List<Sid> sids = new LinkedList<>();
        sids.add(new PrincipalSid(SecurityContextHolder.getContext().getAuthentication().getName()));

        List<ObjectIdentity> childObjects = aclService.findChildren(objectIdentity);
        Map<ObjectIdentity, Acl> resultUser = aclService.readAclsById(childObjects, sids);

        // Assert
        assertThat(childObjects.size(), is(equalTo(3)));
        assertThat(resultUser.keySet().size(), is(equalTo(3)));
        // permissions for the 3rd child are inherited from its parent though not copied to the child directly! A
        // permission evaluator therefore has to check whether isEntriesInheriting is true and check the ancestors for
        // permissions as well
        resultUser.keySet().forEach(objectIdentity1 -> {
            Acl acl = resultUser.get(objectIdentity1);
            checkPermissions(acl);
        });
    }

    @Test
    @WithMockUser
    public void issue3_testReadAclsByIdTwice() throws Exception {
        // Arrange
        TestDomainObject domainObject = new TestDomainObject();
        TestDomainObject firstObject = new TestDomainObject();
        TestDomainObject secondObject = new TestDomainObject();
        TestDomainObject thirdObject = new TestDomainObject();
        TestDomainObject unrelatedObject = new TestDomainObject();

        ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(domainObject.getClass().getName()), domainObject.getId());

        MongoAcl parent = new MongoAcl(domainObject.getId(), domainObject.getClass().getName(), UUID.randomUUID().toString(),new MongoSid("owner"), null, true);
        MongoAcl child1 = new MongoAcl(firstObject.getId(), firstObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Tim Test"), parent.getId(), true);
        MongoAcl child2 = new MongoAcl(secondObject.getId(), secondObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Petty Pattern"), parent.getId(), true);
        MongoAcl child3 = new MongoAcl(thirdObject.getId(), thirdObject.getClass().getName(), UUID.randomUUID().toString(), new MongoSid("Sam Sample"), parent.getId(), true);
        MongoAcl nonChild = new MongoAcl(unrelatedObject.getId(), unrelatedObject.getClass().getName(), UUID.randomUUID().toString());

        DomainObjectPermission user0Permissions = new DomainObjectPermission(UUID.randomUUID().toString(),
                                                                       new MongoSid("user-0"),
                                                                       BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
                                                                       true, true, true);
        DomainObjectPermission user1Permissions = new DomainObjectPermission(UUID.randomUUID().toString(),
                                                                       new MongoSid("user-1"),
                                                                       BasePermission.READ.getMask() | BasePermission.WRITE.getMask(),
                                                                       true, true, true);

        // child3 inherits permission of parent
        parent.getPermissions().add(user0Permissions);
        child1.getPermissions().add(user0Permissions);
        child2.getPermissions().add(user0Permissions);

        // child3 has no permission to inherit from
        child1.getPermissions().add(user1Permissions);
        child2.getPermissions().add(user1Permissions);

        aclRepository.save(parent);
        aclRepository.save(child1);
        aclRepository.save(child2);
        aclRepository.save(child3);
        aclRepository.save(nonChild);

        // Act
        List<Sid> sids = new LinkedList<>();
        sids.add(new PrincipalSid("owner"));

        List<Sid> sids1 = new LinkedList<>();
        sids1.add(new PrincipalSid("user-0"));

        List<Sid> sids2 = new LinkedList<>();
        sids2.add(new PrincipalSid("user-1"));

        List<ObjectIdentity> childObjects = aclService.findChildren(objectIdentity);

        Map<ObjectIdentity, Acl> resultOwner = aclService.readAclsById(childObjects, sids);
        Map<ObjectIdentity, Acl> resultUser = aclService.readAclsById(childObjects, sids1);
        try {
            aclService.readAclsById(childObjects, sids2);
            fail("Method should have thrown a NotFoundException as child3 ACL does not define any permissions for user-1");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(NotFoundException.class));
        }

        // Assert
        assertThat(childObjects.size(), is(equalTo(3)));
        assertThat(resultUser.keySet().size(), is(equalTo(3)));
        resultUser.keySet().forEach(objectIdentity1 -> {
            Acl acl = resultUser.get(objectIdentity1);
            checkPermissions(acl);
        });
        assertThat(resultUser.keySet().size(), is(equalTo(3)));

        assertThat(resultOwner, is(equalTo(resultUser)));
    }

    private void checkPermissions(Acl acl) {
        Set<AccessControlEntry> permissions = new LinkedHashSet<>();
        Acl _parent = acl.getParentAcl();
        if (acl.isEntriesInheriting()) {
            while (null != _parent) {
                permissions.addAll(_parent.getEntries());
                if (_parent.isEntriesInheriting()) {
                    _parent = _parent.getParentAcl();
                }
            }
        }

        assertThat("ACE " + acl + " did not contain or inherit the correct permissions",
                   permissions.size(), is(equalTo(1)));
    }
}
