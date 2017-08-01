package org.springframework.security.acls.mongodb;

import java.util.List;
import java.util.UUID;
import javax.annotation.Resource;
import org.springframework.security.acls.dao.AclRepository;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.DomainObjectPermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.MongoAcl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * Provides a base MongoDB implementation of {@link MutableAclService}.
 * <p>
 * This implementation will map ACL related classes like {@link Acl}, {@link AccessControlEntry} and {@link Sid} to a
 * {@link MongoAcl} POJO class which is persisted or accessed via a MongoDB based repository. This POJO will contain all
 * the ACL relevant data for a domain object in a non flat structure. Due to the non-flat structure lookups and updates
 * are relatively trivial compared to the SQL based {@link AclService} implementation.
 *
 * @author Ben Alex
 * @author Johannes Zlattinger
 * @author Roman Vottner
 */
public class MongoDBMutableAclService extends MongoDBAclService implements MutableAclService {

    @Resource
    private AclRepository aclRepository;
    private final AclCache aclCache;

    public MongoDBMutableAclService(LookupStrategy lookupStrategy, AclCache aclCache)
    {
        super(lookupStrategy);
        this.aclCache = aclCache;
    }

    @Override
    public MutableAcl createAcl(ObjectIdentity objectIdentity) throws AlreadyExistsException {
        Assert.notNull(objectIdentity, "Object Identity required");

        MongoAcl availableAcl =
                aclRepository.findByInstanceIdAndClassName(objectIdentity.getIdentifier(), objectIdentity.getType());

        if (null != availableAcl) {
            throw new AlreadyExistsException("Object identity '" + objectIdentity + "' already exists");
        }

        // Need to retrieve the current principal, in order to know who "owns" this ACL
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        PrincipalSid sid = new PrincipalSid(auth);

        MongoAcl mongoAcl = new MongoAcl(objectIdentity.getIdentifier(),
                                         objectIdentity.getType(),
                                         UUID.randomUUID().toString(),
                                         sid.getPrincipal(),
                                         null,
                                         true);

        aclRepository.save(mongoAcl);

        // Retrieve the ACL via superclass (ensures cache registration, proper retrieval etc)
        Acl acl = readAclById(objectIdentity);
        Assert.isInstanceOf(MutableAcl.class, acl, "MutableAcl should be returned");

        return (MutableAcl) acl;
    }

    @Override
    public void deleteAcl(ObjectIdentity objectIdentity, boolean deleteChildren) throws ChildrenExistException {
        Assert.notNull(objectIdentity, "Object Identity required");
        Assert.notNull(objectIdentity.getIdentifier(),
                       "Object Identity doesn't provide an identifier");

        List<ObjectIdentity> children = findChildren(objectIdentity);
        if (deleteChildren) {
            if (children != null) {
                for (ObjectIdentity child : children) {
                    deleteAcl(child, true);
                }
            }
        } else if (!children.isEmpty()) {
            throw new ChildrenExistException("Cannot delete '" + objectIdentity + "' (has " + children.size() + " children)");
        }

        Long numRemoved = aclRepository.deleteByInstanceId(objectIdentity.getIdentifier());
        if (null == numRemoved || numRemoved < 1) {
            // TODO: log warning that no ACL was found for the domain object
        }

        // Clear the cache
        aclCache.evictFromCache(objectIdentity);
    }

    @Override
    public MutableAcl updateAcl(MutableAcl acl) throws NotFoundException {

        MongoAcl mongoAcl = aclRepository.findById(acl.getId().toString());

        // Delete this ACL's ACEs in the acl_entry table
        mongoAcl.getPermissions().clear();

        for (AccessControlEntry _ace : acl.getEntries()) {
            AccessControlEntryImpl ace = (AccessControlEntryImpl)_ace;
            String sid = null;
            String aceId = (String)ace.getId();
            if (null == aceId) {
                aceId = UUID.randomUUID().toString();
            }
            if (ace.getSid() instanceof PrincipalSid) {
                PrincipalSid principal = (PrincipalSid)ace.getSid();
                sid = principal.getPrincipal();
            } else if (ace.getSid() instanceof GrantedAuthoritySid) {
                GrantedAuthoritySid grantedAuthority = (GrantedAuthoritySid)ace.getSid();
                sid = grantedAuthority.getGrantedAuthority();
            }
            DomainObjectPermission permission =
                    new DomainObjectPermission(aceId, sid, ace.getPermission().getMask(),
                                               ace.isGranting(), ace.isAuditSuccess(), ace.isAuditFailure());
            mongoAcl.getPermissions().add(permission);
        }

        // Update the acl entry
        aclRepository.save(mongoAcl);

        // Clear the cache, including children
        clearCacheIncludingChildren(acl.getObjectIdentity());

        // Retrieve the ACL via superclass (ensures cache registration, proper retrieval etc)
        return (MutableAcl) readAclById(acl.getObjectIdentity());
    }

    private void clearCacheIncludingChildren(ObjectIdentity objectIdentity) {
        Assert.notNull(objectIdentity, "ObjectIdentity required");
        List<ObjectIdentity> children = findChildren(objectIdentity);
        if (children != null) {
            for (ObjectIdentity child : children) {
                clearCacheIncludingChildren(child);
            }
        }
        aclCache.evictFromCache(objectIdentity);
    }
}
