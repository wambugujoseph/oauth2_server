package com.sds.authorization.server.model;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

/**
 * Created by Kibe Joseph Wambugu
 * User: Joseph
 * Day: Friday
 * Date: 12/20/2019
 * Project: CloudHealthAuthorizationService
 */

@Entity
@Table(name = "permission")
@Getter
@Setter
@ToString
public class Permission implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;
    @Column(name = "name")
    private String name;

}

