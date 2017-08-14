package org.springframework.security.acls.mongodb;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.ArrayList;
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
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.MongoAcl;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAcl;
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
 * <p>
 * Note: Similar to the SQL based version of the basic lookup strategy, this implementation will ignore any list
 * containing {@link Sid Sids} passed in as arguments in {@link #readAclsById(List, List)}.
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
            if (definesAccessPermissionsForSids(acl, sids)) {
              result.put(acl.getObjectIdentity(), acl);
              aclFound = true;
            }
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

    for (MongoAcl foundAcl : new ArrayList<>(foundAcls)) {
      Acl acl = null;
      try {
        acl = convertToAcl(foundAcl, foundAcls);
      } catch (ClassNotFoundException cnfEx) {
        // TODO: add exception logging
      }
      if (null != acl) {
        // check if the ACL does define access rules for any of the sids available in the given list
        // owners and parent owners have full access on the ACE/domain object while other users have to be looked up
        // within the permissions
        if (definesAccessPermissionsForSids(acl, sids) ) {
          resultMap.put(acl.getObjectIdentity(), acl);
        }
      }
    }

    return resultMap;
  }

  /**
   * Converts the internal MongoDB representation to a Spring Security ACL instance.
   *
   * @param mongoAcl  The internal MongoDB based data model to convert to a Spring Security ACL one
   * @param foundAcls A list of already fetched MongoDB based data model instances
   * @return The converted Spring Security ACL instance filled with values taken from the MongoDB based data model
   * @throws ClassNotFoundException If no class representation could be found for the domain object the ACL is referring
   * to
   */
  private Acl convertToAcl(MongoAcl mongoAcl, List<MongoAcl> foundAcls) throws ClassNotFoundException {
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
        if (!foundAcls.contains(parentAcl)) {
          foundAcls.add(parentAcl);
        }
        Acl cachedParent = aclCache.getFromCache(new ObjectIdentityImpl(parentAcl.getClassName(), parentAcl.getInstanceId()));
        if (null == cachedParent) {
          parent = convertToAcl(parentAcl, foundAcls);
          aclCache.putInCache((MutableAcl)parent);
        } else {
          parent = cachedParent;
        }
      } else {
        // TODO: Log warning that no parent could be found
      }
    }
    ObjectIdentity objectIdentity = new ObjectIdentityImpl(Class.forName(mongoAcl.getClassName()), mongoAcl.getInstanceId());
    Sid owner;
    if (mongoAcl.getOwner().isPrincipal()) {
      owner = new PrincipalSid(mongoAcl.getOwner().getName());
    } else {
      owner = new GrantedAuthoritySid(mongoAcl.getOwner().getName());
    }
    AclImpl acl = new AclImpl(objectIdentity, mongoAcl.getId(), aclAuthorizationStrategy, grantingStrategy, parent,
                              null, mongoAcl.isInheritPermissions(), owner);

    for (DomainObjectPermission permission : mongoAcl.getPermissions()) {
      Sid sid;
      if (permission.getSid().isPrincipal()) {
        sid = new PrincipalSid(permission.getSid().getName());
      } else {
        sid = new GrantedAuthoritySid(permission.getSid().getName());
      }
      Permission permissions = permissionFactory.buildFromMask(permission.getPermission());
      AccessControlEntryImpl ace =
              new AccessControlEntryImpl(permission.getId(), acl, sid, permissions,
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

  /**
   * Checks whether a fetched ACL specifies any of the {@link Sid Sids} passed in.
   * <p>
   * This implementation will first check if the owner of the domain object is contained in the list and if not check if
   * any of the defined permissions are targeted at a security identity defined in the given list. In case a parent ACL
   * is defined, this implementation will also try to determine whether the owner of an ancestor ACL is found in the
   * given list or any of the permissions defined by an ancestor does contain identities available in the provided list.
   *
   * @param acl  The {@link Acl} instance to check whether it defines at least one of the identities provided
   * @param sids A list of security identities the ACL should be checked against whether it defines at least one of
   *             these
   * @return <tt>true</tt> if the given ACL specifies at least one security identity available within the given list of
   * identities. <tt>false</tt> if none of the passed in security identities could be found in either the provided ACL
   * or any of its ancestor permissions
   */
  protected boolean definesAccessPermissionsForSids(Acl acl, List<Sid> sids) {
    // check whether the list of sids is a match-all list or if the owner is found within the list
    if (sids == null || sids.isEmpty() || sids.contains(acl.getOwner())) {
      return true;
    }
    // check the contained permissions for permissions granted to a certain user available in the provided list of sids
    if (hasPermissionsForSids(acl, sids)) {
      return true;
    }
    // check if a parent reference is available and inheritance is enabled
    if (acl.getParentAcl() != null && acl.isEntriesInheriting()) {
      if (definesAccessPermissionsForSids(acl.getParentAcl(), sids)) {
        return true;
      }

      if (hasPermissionsForSids(acl.getParentAcl(), sids)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks whether the provided ACL contains permissions issued for any of the given security identities.
   *
   * @param acl  The {@link Acl} instance to check whether it contains permissions issued for any of the provided
   *             security identities
   * @param sids A list of security identities the Acl instance should be checked against if it defines permissions for
   *             any of the contained identities
   * @return <tt>true</tt> if the ACL defines at least one permission for a security identity available within the given
   * list of security identities. <tt>false</tt> if none of the permissions specified in the given Acl does define
   * access rules for any identity available in the list of security entities passed in
   */
  protected boolean hasPermissionsForSids(Acl acl, List<Sid> sids) {
    for (AccessControlEntry ace : acl.getEntries()) {
      if (sids.contains(ace.getSid())) {
        return true;
      }
    }
    return false;
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
