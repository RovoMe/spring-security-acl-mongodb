package org.springframework.security.acls.domain;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.core.context.SecurityContextHolder;
import sun.plugin.liveconnect.SecurityContextHelper;

/**
 * Represents an access control list configuration for a domain object specified by its unique identifier. An instance
 * of this class defines an owner of a domain object, a parent ACL configuration instance, which it may inherit
 * permissions from, as well as a list of user permissions for the referenced domain object.
 * <p>
 * This class is a mapping class for {@link Acl} instances which should be persisted to a MongoDB database.
 */
@Document(collection = "ACL")
public class MongoAcl
{
    /** The unique identifier of the ACL pointing to some domain object **/
    @Id
    private Serializable id;
    /** The fully qualified class name of the domain object **/
    private String className;
    /** A reference to the unique identifier of the domain object this ACL was created for **/
    private Serializable instanceId;
    /** The unique identifier of the user owning the domain object **/
    private String owner;
    /** A reference to a parent ACL which may inherit permissions. Can be null **/
    private Serializable parentId = null;
    /**
     * Defines whether to inherit permissions from parent ACL or not. If set to true permissions will be inherited from
     * parent ACLs
     **/
    private boolean inheritPermissions = true;
    /** A list containing access control permissions per user on the domain object this ACL references to **/
    private List<DomainObjectPermission> permissions = new ArrayList<>();

    public MongoAcl() {

    }

    /**
     * Creates a new access control list instance for a domain object identified by the given <em>instanceId</em> unique
     * identifier. The class of the domain object is identified via the provided <em>className</em> argument.
     *
     * @param instanceId The unique identifier of the domain object a new access control list should be generated for
     * @param className  The fully qualified class name of the domain object
     * @param id         The unique identifier of this access control list
     */
    public MongoAcl(Serializable instanceId, String className, Serializable id) {
        this.id = id;
        this.instanceId = instanceId;
        this.className = className;
        // assign the user who created the object as owner
        this.owner = SecurityContextHolder.getContext().getAuthentication().getName();
    }

    /**
     * Creates a new access control list instance for a domain object identified by the given <em>instanceId</em> unique
     * identifier. The class of the domain object is identified via the provided <em>className</em> argument.
     *
     * @param instanceId        The unique identifier of the domain object a new access control list should be generated
     *                          for
     * @param className         The fully qualified class name of the domain object
     * @param id                The unique identifier of this access control list
     * @param owner             The owner of the domain object. Note an owner has full access to the domain object
     * @param parentId          A unique identifier to a parent access control list which contains permissions which are
     *                          inherited if <em>entriesInheriting</em> argument is set to true
     * @param entriesInheriting If set to true will include checking permissions from ancestor access control list
     *                          entries
     */
    public MongoAcl(Serializable instanceId, String className, Serializable id, String owner,
                    Serializable parentId, boolean entriesInheriting) {
        this(instanceId, className, id);
        this.parentId = parentId;
        this.owner = owner;
        this.inheritPermissions = entriesInheriting;
    }

    /**
     * Returns the name of the domain object class this ACL is referring to .
     *
     * @return The class name of the referenced domain object
     */
    public String getClassName() {
        return this.className;
    }

    /**
     * Returns the unique identifier of the domain object referenced by this ACL.
     *
     * @return The unique identifier of the domain object
     */
    public Serializable getInstanceId() {
        return this.instanceId;
    }

    /**
     * Returns the owner name this ACL defines on the domain object.
     *
     * @return The name of the owner of the domain object
     */
    public String getOwner() {
        return this.owner;
    }

    /**
     * Returns the unique identifier of this ACL instance.
     *
     * @return The unique identifier of this ACL
     */
    public Serializable getId() {
        return this.id;
    }

    /**
     * Defines if ancestor permissions should be taken into account when evaluating access permissions on the domain
     * object.
     *
     * @return <tt>true</tt> if permissions from ancestor ACLs are evaluated on accessing the domain object;
     * <tt>false</tt> otherwise
     */
    public boolean isInheritPermissions() {
        return this.inheritPermissions;
    }

    /**
     * Returns the unique identifier of the parent ACL instance if specified.
     *
     * @return The unique identifier of the parent ACL or null if no parent was specified
     */
    public Serializable getParentId() {
        return this.parentId;
    }

    /**
     * Returns the permissions on the domain object monitored by this ACL instance.
     *
     * @return A list of user permissions on the domain object monitored by this ACL
     */
    public List<DomainObjectPermission> getPermissions() {
        return this.permissions;
    }

    /**
     * Specifies the unique identifier of the parent ACL.
     *
     * @param parentId The unique identifier of the parent ACL
     */
    public void setParentId(String parentId) {
        this.parentId = parentId;
    }

    /**
     * Specifies the user permissions on the domain object monitored by this ACL instance.
     *
     * @param permissions The user permissions on the domain object
     */
    public void setPermissions(List<DomainObjectPermission> permissions) {
        this.permissions = permissions;
    }

    /**
     * Specifies whether parent access permisssions should be taken into account when evaluating user access permissions
     * on a domain object.
     *
     * @param inheritPermissions <tt>true</tt> if parent permissions should be evaluated on user access of the domain
     *                           object; <tt>false</tt> if only the permissions by this ACL should be reconsidered on
     *                           evaluating access permissions
     */
    public void setInheritPermissions(boolean inheritPermissions) {
        this.inheritPermissions = inheritPermissions;
    }
}
