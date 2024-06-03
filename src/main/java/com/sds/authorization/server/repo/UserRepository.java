package com.sds.authorization.server.repo;

import com.sds.authorization.server.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author Joseph Kibe
 * Created on May 31, 2024.
 * Time 11:59 AM
 */

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmailOrUsername(String email, String username);

}
