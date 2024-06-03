package com.sds.authorization.server.repo;

import com.sds.authorization.server.model.OauthClientDetails;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author Joseph Kibe
 * Created on June 03, 2024.
 * Time 9:37 AM
 */

public interface OauthClientRepository extends JpaRepository<OauthClientDetails, String> {
}
