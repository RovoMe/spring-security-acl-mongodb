package org.springframework.security.acls.domain;

/**
 * Represents a security identity assignable to certain permissions in an access control list. The identity can either
 * be a user principal or a granted authority. If {@link #isPrincipal} returns true, the security identity represents an
 * authenticated user, otherwise an instance of this class will represent a granted authority.
 *
 * @author Roman Vottner
 */
public class MongoSid {
    /** The name of the security identity **/
    private String name;
    /** Defines whether this security identity is a user principal (true) or a granted authority (false) **/
    private boolean isPrincipal;

    /**
     * Default constructor needed by Spring.
     */
    public MongoSid() {

    }

    /**
     * Creates a new security identity which represents a user principal assignable to permissions in an access control
     * list.
     *
     * @param name The name of the user principal this security identity is created for
     */
    public MongoSid(String name) {
        this.name = name;
        this.isPrincipal = true;
    }

    /**
     * Creates a new security identity assignable to permissions in an access control list. This constructor differs
     * from {@link #MongoSid(String)} by allowing to specify the actual type of security identity to create.
     *
     * @param name        The name of the user or role this security identity is created for
     * @param isPrincipal Defines whether this security identity represents a user principal (true) or a granted
     *                    authority (false)
     */
    public MongoSid(String name, boolean isPrincipal) {
        this.name = name;
        this.isPrincipal = isPrincipal;
    }

    /**
     * Returns the name of the security identity. In case {@link #isPrincipal} returns true, this is the user name,
     * otherwise it will match the role name of the granted authority.
     *
     * @return The name of the security identity
     */
    public String getName() {
        return this.name;
    }

    /**
     * Defines the new name of this security identity instance.
     *
     * @param name The name to assign to the security identity.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Defines whether this security identity is a user principal (true) or a granted authority (false).
     *
     * @return <tt>true</tt> in case this instance represents a user principal, <tt>false</tt> for granted authorities
     */
    public boolean isPrincipal() {
        return this.isPrincipal;
    }

    /**
     * Specifies whether this instance is a user principal or a granted authority.
     *
     * @param isPrincipal If set to <tt>true</tt> will mark this security identity instance as a user principal. On
     *                    providing <tt>false</tt> this instance will represent a granted authority
     */
    public void setPrincipal(boolean isPrincipal) {
        this.isPrincipal = isPrincipal;
    }
}
