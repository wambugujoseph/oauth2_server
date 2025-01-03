package com.sds.authorization.server.repo;

import com.sds.authorization.server.model.User;
import jakarta.persistence.ManyToMany;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * @author Joseph Kibe
 * Created on May 31, 2024.
 * Time 11:59 AM
 */

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmailAndStatus(String email, String status);
    Optional<User> findByEmail(String email);


    @Modifying
    @Transactional
    @Query(value = """
            UPDATE users u
            SET
            failed_login_attempt = (failed_login_attempt + 1),
            status='LOCKED',
            last_failed_login_time = CURRENT_TIMESTAMP
            WHERE
            email=:email
            """, nativeQuery = true)
    void lockeUserAccountFailedLogin(@Param("email") String email);

    @Modifying
    @Transactional
    @Query(value = """
            UPDATE users
            SET
            failed_login_attempt = (failed_login_attempt + 1),
            last_failed_login_time = CURRENT_TIMESTAMP
            WHERE
            email=:email
            """, nativeQuery = true)
    void recordUserFailedLoginAttempt(@Param("email") String email);


    @Modifying
    @Transactional
    @Query(value = """
            UPDATE users
            SET
            password=:new_pass,
            last_failed_login_time = CURRENT_TIMESTAMP
            WHERE
            email=:email
            """, nativeQuery = true)
    void updateUserPassword(@Param("email") String email, @Param("new_pass") String hashedPassword);


}
