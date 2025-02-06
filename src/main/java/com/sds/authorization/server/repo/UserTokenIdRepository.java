package com.sds.authorization.server.repo;


import com.sds.authorization.server.model.UserTokenId;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author joseph.kibe
 * Created On 06/02/2025 08:50
 **/

@Repository
public interface UserTokenIdRepository extends JpaRepository<UserTokenId, String> {

    @Modifying
    @Transactional
    @Query("UPDATE UserTokenId u set u.status=:status, u.updatedAt=current_timestamp WHERE u.userEmail=:email and u.tokenId=:token_id")
    void updateUserTokenIdStatus(@Param("status") String status,
                                 @Param("token_id") String tokenId,
                                 @Param("email") String email);

    @Modifying
    @Transactional
    @Query("UPDATE UserTokenId u set u.status=:status, u.updatedAt=current_timestamp WHERE u.userEmail=:email and u.loggedInApp=:logged_in_app")
    void updateUserTokenIdStatusByEmailAndLoggedInApp(@Param("status") String status,
                                                      @Param("email") String email,
                                                      @Param("logged_in_app") String loggedInApp);

    @Modifying
    @Transactional
    @Query("UPDATE UserTokenId u set u.status=:status, u.updatedAt=current_timestamp WHERE u.userEmail=:email ")
    void updateUserTokenIdStatus(@Param("status") String status,
                                 @Param("email") String email);

    Optional<UserTokenId> findByTokenIdAndStatus(String tokenId, String status);


}
