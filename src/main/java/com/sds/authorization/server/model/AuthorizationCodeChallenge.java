package com.sds.authorization.server.model;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.sql.Timestamp;

/**
 * @author joseph.kibe
 * Created On 14/12/2024 22:42
 **/

@Entity
@Table(name = "authorization_code_challenge")
@Getter
@Setter
@ToString
public class AuthorizationCodeChallenge {

    @Id
    @Column(name = "code_challenge_id")
    private String codeChallengeId;
    @Column(name = "created_at")
    private Timestamp createdAt;
    @Column(name = "updated_at")
    private Timestamp updatedAt;
    @Column(name = "code_challenge")
    private String codeChallenge;
    @Column(name = "code_challenge_method")
    private String codeChallengeMethod;
    @Column(name = "redirect_url")
    private String redirectUrl;
    @Column(name = "client_id")
    private String clientId;
    @Column(name = "username")
    private String username;
    @Column(name = "response_type")
    private String responseType;
    @Column(name = "expire_at")
    private long expireAt;
    @Column(name = "is_challenge_used")
    private boolean isChallengeUsed;
}
