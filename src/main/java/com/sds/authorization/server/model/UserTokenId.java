package com.sds.authorization.server.model;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.sql.Timestamp;

/**
 * @author joseph.kibe
 * Created On 06/02/2025 08:45
 **/

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
@Entity
@Table(name = "user_token_id")
public class UserTokenId {

    @Column(name = "user_email")
    private String userEmail;
    @Column(name = "logged_in_device_count")
    private long loggedInDeviceCount;
    @Column(name = "logged_in_device", length = 500)
    private String loggedInDevice;
    @Column(name = "logged_in_app")
    private String loggedInApp;
    @Id
    @Column(name = "token_id")
    private String tokenId;
    @Column(name = "created_at")
    private Timestamp createdAt;
    @Column(name = "updated_at")
    private Timestamp updatedAt;
    @Column(name = "expire_at")
    private Timestamp expireAt;
    @Column(name = "status")
    private String status;
}
