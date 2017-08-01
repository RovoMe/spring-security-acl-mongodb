package org.springframework.security.acls.mongodb;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.AuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.DomainObjectPermission;
import org.springframework.security.acls.domain.MongoAcl;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;

import java.util.List;
import java.util.Map;
import org.springframework.security.util.FieldUtils;
import org.springframework.util.Assert;

import static org.springframework.data.mongodb.core.query.Query.query;

/**
 * Performs lookups against a MongoDB data store. This strategy class will take care of reading a POJO representation of
 * ACL documents from a MongoDB database and converting the results to proper Spring Security ACL instances. As with the
 * SQL based lookup strategy implementation, this implementation will make use of caching retrieved ACLs and providing
 * cached results on subsequent queries.
 *
 * @author Roman Vottner
 */
public class BasicLookupStrategy implements LookupStrategy {

  /** Spring template for interacting with a MongoDB database **/
  private MongoTemplate mongoTemplate;
  /** Used to avoid further database lookups for already retrieved Acl instances **/
  private AclCache aclCache;
  /**
   * A Spring Security authorization strategy passed to the generated Acl implementation once the data are loaded from
   * the database. This strategy checks whether existing permission entries for users may be removed or new ones added.
   */
  private AclAuthorizationStrategy aclAuthorizationStrategy;
  /**
   * This strategy implementation will be injected into the generated Spring Security Acl class after retrieving the
   * data from the database
   **/
  private PermissionGrantingStrategy grantingStrategy;
  /** Used to convert the int value containing the permission value back to a permission object used by Spring security **/
  private PermissionFactory permissionFactory = new DefaultPermissionFactory();

  /** The number of ACLs retrieved at maximum in one go **/
  private int batchSize = 50;

  /**
   * Used to add respective user permissions on a domain object to an ACL instance as the setter requires elevated
   * permission and the actual list returned is a copy and hence adding the permission to the list does not work that
   * way
   **/
  private final Field fieldAces = FieldUtils.getField(AclImpl.class, "aces");

  public BasicLookupStrategy(MongoTemplate mongoTemplate, AclCache aclCache,
                             AclAuthorizationStrategy aclAuthorizationStrategy,
                             AuditLogger auditLogger) {
    this(mongoTemplate, aclCache, aclAuthorizationStrategy, new DefaultPermissionGrantingStrategy(auditLogger));
  }

  public BasicLookupStrategy(MongoTemplate mongoTemplate, AclCache aclCache,
                             AclAuthorizationStrategy aclAuthorizationStrategy,
                             PermissionGrantingStrategy grantingStrategy) {
    Assert.notNull(aclCache, "AclCache required");
    Assert.notNull(aclAuthorizationStrategy, "AclAuthorizationStrategy required");
    Assert.notNull(grantingStrategy, "grantingStrategy required");
    this.mongoTemplate = mongoTemplate;
    this.aclCache = aclCache;
    this.aclAuthorizationStrategy = aclAuthorizationStrategy;
    this.grantingStrategy = grantingStrategy;

    fieldAces.setAccessible(true);
  }

  @Override
  public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids) {

    Map<ObjectIdentity, Acl> result = new HashMap<>();
    Set<ObjectIdentity> currentBatchToLoad = new HashSet<>();

    for (int i=0; i < objects.size(); i++) {
      final ObjectIdentity oid = objects.get(i);
      boolean aclFound = false;

      // Check we don't already have this ACL in the results
      if (result.containsKey(oid)) {
        aclFound = true;
      }

      // Check cache for the present ACL entry
      if (!aclFound) {
        Acl acl = aclCache.getFromCache(oid);

        // Ensure any cached element supports all the requested SIDs
        // (they should always, as our base impl doesn't filter on SID)
        if (acl != null) {
          if (acl.isSidLoaded(sids)) {
            result.put(acl.getObjectIdentity(), acl);
            aclFound = true;
          } else {
            throw new IllegalStateException("Error: SID-filtered element detected when implementation does not perform SID filtering "
                                            + "- have you added something to the cache manually?");
          }
        }
      }

      // Load the ACL from the database
      if (!aclFound) {
        currentBatchToLoad.add(oid);
      }

      // Is it time to load from Mongo the currentBatchToLoad?
      if ((currentBatchToLoad.size() == this.batchSize) || ((i + 1) == objects.size())) {
        if (currentBatchToLoad.size() > 0) {
          Map<ObjectIdentity, Acl> loadedBatch = lookupObjectIdentities(currentBatchToLoad, sids);

          // Add loaded batch (all elements 100% initialized) to results
          result.putAll(loadedBatch);

          currentBatchToLoad.clear();
        }
      }
    }

    return result;
  }

  /**
   * Looks up a batch of <code>ObjectIdentity</code>s directly from the database.
   * <p>
   * The caller is responsible for optimization issues, such as selecting the identities
   * to lookup, ensuring the cache doesn't contain them already, and adding the returned
   * elements to the cache etc.
   * <p>
   * This subclass is required to return fully valid <code>Acl</code>s, including
   * properly-configured parent ACLs.
   *
   */
  private Map<ObjectIdentity, Acl> lookupObjectIdentities(
          final Collection<ObjectIdentity> objectIdentities, List<Sid> sids) {
    Assert.notEmpty(objectIdentities, "Must provide identities to lookup");

    Set<Serializable> objectIds = new LinkedHashSet<>();
    Set<String> types = new LinkedHashSet<>();
    for (ObjectIdentity domainObject : objectIdentities) {
      objectIds.add(domainObject.getIdentifier());
      types.add(domainObject.getType());
    }
    Criteria where = Criteria.where("instanceId").in(objectIds).and("className").in(types);
    List<MongoAcl> foundAcls = mongoTemplate.find(query(where).with(new Sort(Sort.Direction.ASC, "instanceId", "permissions.position")), MongoAcl.class);

    Map<ObjectIdentity, Acl> resultMap = new HashMap<>();

    for (MongoAcl foundAcl : foundAcls) {
      Acl acl = null;
      try {
        acl = convertToAcl(foundAcl, foundAcls, sids);
      } catch (ClassNotFoundException cnfEx) {
        // TODO: add exception logging
      }
      if (null != acl) {

        resultMap.put(acl.getObjectIdentity(), acl);
      }
    }

    return resultMap;
  }

  private Acl convertToAcl(MongoAcl mongoAcl, List<MongoAcl> foundAcls, List<Sid> loadedSids) throws ClassNotFoundException {
    Acl parent = null;
    if (mongoAcl.getParentId() != null) {
      MongoAcl parentAcl = null;
      // attempt to load a parent ACL from the list of loaded ACLs
      for (MongoAcl found : foundAcls) {
        if (found.getId().equals(mongoAcl.getParentId())) {
          parentAcl = found;
          break;
        }
      }
      // if the parent ACL was not loaded already, try to find it via its id
      if (null == parentAcl) {
        parentAcl = mongoTemplate.findById(mongoAcl.getParentId(), MongoAcl.class);
      }
      if (parentAcl != null) {
        parent = convertToAcl(parentAcl, foundAcls, loadedSids);
      } else {
        // TODO: Log warning that no parent could be found
      }
    }
    ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(mongoAcl.getClassName()), mongoAcl.getInstanceId());
    Sid owner = new PrincipalSid(mongoAcl.getOwner());
    AclImpl acl = new AclImpl(objectIdentity, mongoAcl.getId(), aclAuthorizationStrategy, grantingStrategy, parent,
                              loadedSids, mongoAcl.isInheritPermissions(), owner);

    for (DomainObjectPermission permission : mongoAcl.getPermissions()) {
      Sid user = new PrincipalSid(permission.getSid());
      Permission permissions = permissionFactory.buildFromMask(permission.getPermission());
      AccessControlEntryImpl ace =
              new AccessControlEntryImpl(permission.getId(), acl, user, permissions,
                                         permission.isGranting(), permission.isAuditSuccess(), permission.isAuditFailure());
      // directly adding this permission entry to the Acl isn't possible as the returned list by acl.getEntries()
      // is a copy of the internal list and acl.insertAce(...) requires elevated security permissions
      // acl.getEntries().add(ace);
      // acl.insertAce(acl.getEntries().size(), permissions, user, permission.isGranting());
      List<AccessControlEntryImpl> aces = readAces(acl);
      aces.add(ace);
    }

    // add the loaded ACL to the cache
    aclCache.putInCache(acl);

    return acl;
  }

  private List<AccessControlEntryImpl> readAces(AclImpl acl) {
    try {
      return (List<AccessControlEntryImpl>) fieldAces.get(acl);
    }
    catch (IllegalAccessException e) {
      throw new IllegalStateException("Could not obtain AclImpl.aces field", e);
    }
  }

  /**
   * Sets the {@code PermissionFactory} instance which will be used to convert loaded
   * permission data values to {@code Permission}s. A {@code DefaultPermissionFactory}
   * will be used by default.
   *
   * @param permissionFactory The permission factory to use
   */
  public final void setPermissionFactory(PermissionFactory permissionFactory) {
    this.permissionFactory = permissionFactory;
  }
}
