package com.sds.authorization.server.model;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Generated;
import jakarta.persistence.*;
import jakarta.websocket.server.ServerEndpoint;
import lombok.*;

import java.sql.Timestamp;

/**
 * @author joseph.kibe
 * Created On 21/01/2025 10:49
 **/

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
@Entity
@Table(name = "ui9_pass_reset")
public class PasswordReset {
    @Id
    @GeneratedValue(strategy =GenerationType.TABLE )
    @JsonProperty("id")
    @Column(name = "id")
    private long id;

    @JsonProperty("user_id")
    @Column(name = "user_id")
    private String userId;

    @JsonProperty("reset_token")
    @Column(name = "reset_token")
    private String resetToken;

    @JsonProperty("responseType")
    @Column(name = "responseType")
    private String responseType;

    @JsonProperty("clientId")
    @Column(name = "clientId")
    private String clientId;

    @JsonProperty("redirectUrl")
    @Column(name = "redirectUrl")
    private String redirectUrl;

    @JsonProperty("state")
    @Column(name = "state")
    private String state;

    @JsonProperty("code_challenge")
    @Column(name = "code_challenge")
    private String codeChallenge;

    @JsonProperty("code_challenge_method")
    @Column(name = "code_challenge_method")
    private String codeChallengeMethod;

    @JsonProperty("used_state")
    @Column(name = "used_state")
    private String usedState;

    @JsonProperty("password")
    @Column(name = "password")
    private String password;

    @JsonProperty("created_at")
    @Column(name = "created_at")
    private Timestamp createdAt;

    @JsonProperty("updated_at")
    @Column(name = "updated_at")
    private Timestamp updatedAt;

    @JsonProperty("client_name")
    @Column(name = "client_name")
    private String clientName;

}
