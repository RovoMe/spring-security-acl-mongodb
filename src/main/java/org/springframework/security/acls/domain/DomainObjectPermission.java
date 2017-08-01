package org.springframework.security.acls.domain;

import java.io.Serializable;
import org.springframework.util.Assert;

/**
 * Represents a permission setting per user for a domain object referenced by the {@link MongoAcl} instance which
 * holds instances of this class.
 * <p>
 * This class is a mapping class for {@link org.springframework.security.acls.model.AccessControlEntry} instances which
 * are persisted into a MongoDB database. Instead of keeping the data separated into different collections, similar to
 * the SQL approach, permissions are embedded into the Mongo ACL entry. This is necessary as MongoDB does not support
 * table joins, like SQL does, and also keeps data that belong to each other within the same collection entry to avoid
 * lookup time.
 */
public class DomainObjectPermission
{
    /** The unique identifier of this permission instance **/
    private final Serializable id;
    /** The unique identifier of the user this permission instance is created for **/
    private final String sid;
    /** A bit-mask containing the relevant access permission for the user referenced by {@link #sid}. **/
    private int permission;
    /** Defines whether this permission is specifying granting permissions or denying permissions to a domain object. In
     * case this field is set to false a write permission defined in {@link #permission} will read like deny writes by
     * the user identified by the <tt>sid</tt> for the respective domain object **/
    private final boolean granting;
    /**
     * Defines whether denied access to certain resources should be logged or not. If set to true any security related
     * issues will be logged
     **/
    private boolean auditFailure = false;
    /**
     * Defines whether successful access to certain resources should be logged. If set to true any successful access
     * will be logged
     */
    private boolean auditSuccess = false;

    /**
     * Creates a new permission for a given user identified by its unique identifier passed in as <em>sid</em> parameter.
     * The actual access permission for domain object are encapsulated by a bit-mask provided as <em>permission</em>
     * argument.
     * <p>
     * Note that although a permission for a user is created for a certain domain object, this permission entry is added
     * to the permissions list on the ACL for the respective domain object and hence no reference to the actual domain
     * object or the ACL are stored within an instance of this class.
     *
     * @param id           The unique identifier of this permission entry
     * @param sid          The unique identifier of the user this permission is created for
     * @param permission   A bit-mask defining the actual permission the user identified by the given <em>sid</em>
     *                     argument has on a certain domain object
     * @param granting     Defines if permissions passed are for granting or denying purposes. If this argument is set
     *                     to false any permissions provided will be for deny cases
     * @param auditSuccess Defines if successful access attempts on the domain object by this user should be logged
     * @param auditFailure Defines if failed access attempts on the domain object by this user should be logged
     */
    public DomainObjectPermission(Serializable id, String sid, int permission,
                                  boolean granting, boolean auditSuccess, boolean auditFailure) {
        Assert.notNull(sid, "Sid required");
        this.id = id;
        this.sid = sid;
        this.permission = permission;
        this.granting = granting;
        this.auditSuccess = auditSuccess;
        this.auditFailure = auditFailure;
    }

    /**
     * Returns the unique identifier of this user permission entry.
     *
     * @return The unique identifier of this permission entry
     */
    public Serializable getId() {
        return this.id;
    }

    /**
     * Returns the permissions of the user identified by {@link #sid} as bit mask.
     *
     * @return The user access permissions as bit mask
     */
    public int getPermission() {
        return this.permission;
    }

    /**
     * Returns the name of the user this permission entry was created for.
     *
     * @return The name of the user this permission is for
     */
    public String getSid() {
        return this.sid;
    }

    /**
     * Defines whether a failed access on a domain object by this user should be logged.
     *
     * @return <tt>true</tt> if failed domain object access should be logged; <tt>false</tt> otherwise
     */
    public boolean isAuditFailure() {
        return this.auditFailure;
    }

    /**
     * Defines whether successful domain object access by this user should be logged.
     *
     * @return <tt>true</tt> if successful domain object access should be logged; <tt>false</tt> otherwise
     */
    public boolean isAuditSuccess() {
        return this.auditSuccess;
    }

    /**
     * Specifies whether the permissions returned by {@link #getPermission()} are for a granting or rejecting purpose.
     *
     * @return <tt>true</tt> if permissions returned by {@link #getPermission()} specify granting permissions;
     * <tt>false</tt> will state that permissions returned by {@link #getPermission()} are for rejecting a user on a
     * match.
     */
    public boolean isGranting() {
        return this.granting;
    }

    /**
     * Specifies whether failed domain object access should be logged.
     *
     * @param auditFailure <tt>true</tt> if failed domain object access should be looged; <tt>false</tt> otherwise
     */
    public void setAuditFailure(boolean auditFailure)
    {
        this.auditFailure = auditFailure;
    }

    /**
     * Specifies whether successful domain object access should be logged.
     *
     * @param auditSuccess <tt>true</tt> if successful domain object access should be looged; <tt>false</tt> otherwise
     */
    public void setAuditSuccess(boolean auditSuccess) {
        this.auditSuccess = auditSuccess;
    }

    /**
     * Specifies the access permission for the user returned by {@link #getSid()} on a domain object held by the ACL
     * that holds this permission entry.
     * <p>
     * Access control permissions can be chained together using the bit-operator <em>|</em> like in the sample below
     * which defines read and write access for a certain user:
     * <pre><code>BasePermission.READ.getMask() | BasePermission.WRITE.getMask()</code></pre>
     *
     * @param permission The permission set for a certain user
     */
    public void setPermission(int permission) {
        this.permission = permission;
    }
}
