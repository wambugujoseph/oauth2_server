package com.sds.authorization.server.model;


import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Created by Kibe Joseph Wambugu
 * User: Joseph
 * Day: Friday
 * Date: 12/20/2019
 * Project: CloudHealthAuthorizationService
 */

@Entity
@Getter
@Setter
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Transient
    private String username;

    @Column(name = "user_id", unique = true)
    private String userId;

    @Column(name = "password")
    private String password;

    @Column(name = "email", unique = true)
    private String email;

    @Column(name = "msisdn", unique = true)
    private String phoneNumber;

    @Column(name = "status")
    private String status;

    @Column(name = "partner_name")
    private String partnerName;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "role_name")
    private String roleName;

    @Column(name = "company_name")
    private String companyName;

    @Column(name = "company_id")
    private String companyId;

    @Column(name = "reset_password")
    private boolean resetPassword;

    @Column(name="failed_login_attempt")
    private int failedLoginAttempt;

    @Column(name = "role_id", insertable = false, updatable = false)
    private long roleId;


    @OneToOne(fetch = FetchType.EAGER, cascade = {CascadeType.DETACH, CascadeType.MERGE, CascadeType.PERSIST, CascadeType.REFRESH})
    @JoinColumn(name = "role_id", referencedColumnName = "id")
    private Role role;

}
