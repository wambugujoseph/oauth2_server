package com.sds.authorization.server.repo;


import com.sds.authorization.server.model.PasswordReset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author joseph.kibe
 * Created On 21/01/2025 11:11
 **/

@Repository
public interface PasswordResetRepository extends JpaRepository<PasswordReset, Long> {

    List<PasswordReset> findAllByResetToken(String resetToken);
}
