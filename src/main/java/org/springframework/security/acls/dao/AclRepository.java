package org.springframework.security.acls.dao;

import java.io.Serializable;
import java.util.List;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.security.acls.domain.MongoAcl;
import org.springframework.stereotype.Repository;

/**
 * Spring Data MongoDB repository for {@link MongoAcl} instances.
 */
@Repository
public interface AclRepository extends MongoRepository<MongoAcl, Serializable>
{
    /**
     * Retrieves an access control list by its unique identifier.
     *
     * @param id The unique identifier of the access control list to return
     * @return The ACL instance identified by the given ID
     */
    MongoAcl findById(Serializable id);

    /**
     * Returns the ACL for a given domain object identifier and its class name.
     *
     * @param instanceId The unique identifier of the domain object the ACL should be returned for
     * @param className  The class name of the domain object referenced by the ACL
     * @return The access control list for the matching domain object.
     */
    MongoAcl findByInstanceIdAndClassName(Serializable instanceId, String className);

    /**
     * Retrieves all child ACLs which specified the given <em>parentId</em> as their parent.
     *
     * @param parentId The unique identifier of the parent ACL
     * @return A list of child ACLs for the given parent ACL ID.
     */
    List<MongoAcl> findByParentId(Serializable parentId);

    /**
     * Removes a document from the ACL collection that contains an instanceId field set to the provided value.
     *
     * @param instanceId The unique identifier of the domain object to remove an ACL entry for
     * @return The number of deleted documents
     */
    Long deleteByInstanceId(Serializable instanceId);
}
