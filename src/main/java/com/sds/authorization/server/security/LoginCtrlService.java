package com.sds.authorization.server.security;

import com.sds.authorization.server.configuration.AppProps;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * @author Joseph Kibe
 * Created on January 31, 2024.
 * Time 12:57 AM
 */

@Service
@Slf4j
public class LoginCtrlService {


    private final UserService userService;
    private final AppProps config;

    public LoginCtrlService(UserService userService, AppProps config) {

        this.userService = userService;
        this.config = config;
    }

    /**
     * Handle Brute force attack by counting the number of failed login attempts for a user
     * Max reties 5
     *
     * @param email is the user identifier
     */
    public void userBruteForceAttackPrevention(String email) {
        try {
            User u = userService.getActiveUserByEmail(email);
            if (u != null) {
                int failedAttempt = u.getFailedLoginAttempt();

                if (failedAttempt >= 5) {
                    log.info("BRUTE FORCE DETECTED deactivating USER {} due to {} login failed attempts", email, failedAttempt + 1);

                    userService.lockeUserAccountFailedLogin(email);

                } else {
                    log.info("BRUTE FORCE attack checker USER {} with {} login failed attempts", email, failedAttempt + 1);
                    userService.recordUserFailedLoginAttempt(email);
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    /**
     * Handle Brute force attack by counting the number of failed login attempts for a user OTP
     * Max reties 5
     *
     * @param email is the user identifier
     */
    public void useOTPBruteForceAttackPrevention(String email) {
        userBruteForceClearance(email);
    }

    /**
     * Reactivate user by disabling the account and setting failed login count to 0
     *
     * @param email user identifier
     */
    public void userBruteForceClearance(String email) {
        //userService.registerFailedLoginAttempt(email, 0, "ACTIVE");
    }

    /**
     * Reactive Partner and set password failed attempts to 0
     *
     * @param partnerUsername partner identifier
     */
    public void partnerBruteForceClearance(String partnerUsername) {
        //partnerService.registerFailedLoginAttempt(partnerUsername, 0, "ACTIVE");
    }
}
