package com.sds.authorization.server.repo;


import com.sds.authorization.server.model.AuthorizationCodeChallenge;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/**
 * @author joseph.kibe
 * Created On 14/12/2024 23:07
 **/

public interface CodeChallengeRepo extends JpaRepository<AuthorizationCodeChallenge, String> {

    List<AuthorizationCodeChallenge>  findAllByCode(String code);
    List<AuthorizationCodeChallenge>  findAllByCodeAndClientId(String code, String clientID);
}
