package com.sds.authorization.server.model;


import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.List;

/**
 * Created by Kibe Joseph Wambugu
 * User: Joseph
 * Day: Friday
 * Date: 12/20/2019
 * Project: CloudHealthAuthorizationService
 */

@Entity
@Table(name = "ui9_roles")
@Getter
@Setter
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class Role implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    @Column(name = "id")
    private Long id;

    @Column(name = "role_name")
    private String name;

    @Column(name = "role_id")
    private String roleId;

    @Column(name = "display_name")
    private String displayName;

    @Column(name = "description")
    private String description;

    @Column(name="status")
    private String status;

    @Column(name = "created_at")
    private Timestamp createdAt;

    @Column(name = "updated_at")
    private Timestamp updatedAt;

    @Column(name="created_by")
    private String createdBy;

    @Column(name = "updatedBy")
    private String updateBy;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "ui9_role_permissions", joinColumns =
            @JoinColumn(name = "role_id", referencedColumnName = "id"), inverseJoinColumns =
            @JoinColumn(name = "permission_id", referencedColumnName = "id" ))
    private List<Permission> permissions;


}
