package com.sds.authorization.server.service;


import com.sds.authorization.server.configuration.AppProps;
import com.sds.authorization.server.dto.ChangePasswordRequest;
import com.sds.authorization.server.dto.PasswordResetRequest;
import com.sds.authorization.server.model.*;
import com.sds.authorization.server.repo.PasswordResetRepository;
import com.sds.authorization.server.repo.UserRepository;
import com.sds.authorization.server.security.PasswordGenerator;
import com.sds.authorization.server.security.RSAKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.sds.authorization.server.service.NotificationServiceImpl.PasswordResetEmailTemplate;

/**
 * @author joseph.kibe
 * Created On 21/01/2025 11:12
 **/

@Service
@Slf4j
public class PasswordResetService {

    private final PasswordResetRepository repository;
    private final UserRepository userRepository;
    private final UserService userService;
    private final ClientService clientService;
    private final NotificationService notificationService;
    private final AppProps props;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public PasswordResetService(PasswordResetRepository repository, UserRepository userRepository, UserService userService, ClientService clientService,
                                NotificationService notificationService, AppProps props) {
        this.repository = repository;
        this.userRepository = userRepository;
        this.userService = userService;
        this.clientService = clientService;
        this.notificationService = notificationService;
        this.props = props;
        this.bCryptPasswordEncoder = new BCryptPasswordEncoder(
                BCryptPasswordEncoder.BCryptVersion.$2A, 11, new SecureRandom("XXL".getBytes(StandardCharsets.UTF_8)));
    }

    public CustomResponse initiatePasswordReset(PasswordResetRequest request, boolean isNewUser) {
        User user = userService.getUserByEmail(request.userId());
        OauthClientDetails oauthClientDetails = clientService.getOauthClientDetails(request.clientId());

        if (oauthClientDetails == null) {
            return CustomResponse.builder().responseCode("400").responseDesc("Invalid client").build();
        }

        if (user == null) {
            return CustomResponse.builder()
                    .responseCode("400").responseDesc("The user ID or email provided doesn't exist").build();
        }

        String resetToken = PasswordGenerator.generateRandomPassword(50);
        String encryptedResetToken = getEncryptedResetToken(resetToken);
        PasswordReset passwordReset = PasswordReset.builder()
                .userId(request.userId())
                .resetToken(resetToken)
                .responseType(request.responseType())
                .clientId(request.clientId())
                .redirectUrl(request.redirectUrl())
                .state(request.state())
                .codeChallenge(request.codeChallenge())
                .codeChallengeMethod(request.codeChallengeMethod())
                .password("")
                .usedState("ACTIVE")
                .createdAt(Timestamp.valueOf(LocalDateTime.now()))
                .updatedAt(null)
                .clientName(oauthClientDetails.getApplicationName())
                .build();

        passwordReset = repository.save(passwordReset);

        String url = props.baseUrl() + "/auth/reset-password?reset_token=" + encryptedResetToken;

        if (isNewUser) {
            pushNewAccountPasswordReset(oauthClientDetails.getApplicationName(), url, user.getEmail(), user.getCompanyId());
        } else {
            pushResetEmail(oauthClientDetails.getApplicationName(), url, user.getEmail(),user.getCompanyId());
        }

        return CustomResponse.builder()
                .responseCode("200")
                .responseDesc("A reset link has been sent to your email")
                .build();
    }

    private String getEncryptedResetToken(String plainToken) {
        return RSAKeyGenerator.urlEncryptWithAES(props.cipher(), plainToken.getBytes(StandardCharsets.UTF_8));
    }

    private void pushResetEmail(String product, String link, String email, String companyId) {

        String msg = "<p>You recently requested to reset your password for your " + product + " account. Use the button below to reset it. <strong>This password reset is only valid for the next 2 hours.</strong></p";
        String body = String.format(PasswordResetEmailTemplate, "", msg, link);
        notificationService.sendEmailNotification(Date.from(Instant.now()).getTime() + "", body,
                "PASSWORD RESET", List.of(email).toArray(new String[0]), companyId);
    }

    private void pushNewAccountPasswordReset(String product, String link, String email, String companyId) {
        String msg = "<p>An account has been created on the " + product + ". Use the button below to reset your password. <strong>This password reset is only valid for the next 2 hours.</strong></p";
        String body = String.format(PasswordResetEmailTemplate, "", msg, link);
        notificationService.sendEmailNotification(Date.from(Instant.now()).getTime() + "", body,
                "PASSWORD RESET",
                List.of(email).toArray(new String[0]), companyId);

    }

    public CustomResponse resetPassword(ChangePasswordRequest request) {

        String regExpn = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$";
        Pattern pattern = Pattern.compile(regExpn, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(request.newPass());
        String decryptedResetToken = RSAKeyGenerator.urlDecryptWithAES(props.cipher(), request.passwordResetToken());
        List<PasswordReset> passwordResets = repository.findAllByResetTokenAndUsedStateAndCreatedAtGreaterThan(decryptedResetToken, "ACTIVE", Timestamp.valueOf(LocalDateTime.now().minusMinutes(5)));

        if (!passwordResets.isEmpty()) {
            User user = userService.getUserByEmail(passwordResets.getFirst().getUserId());
            if (matcher.matches() && !hasConsecutiveSequence(request.passwordResetToken(), 3)
                    && !isPasswordContaining(user.getName(), request.newPass())) {
                if (request.confirmPass().equalsIgnoreCase(request.newPass())) {
                    if (!bCryptPasswordEncoder.matches(request.newPass(), user.getPassword())) {
                        PasswordReset passwordReset = passwordResets.getFirst();
                        passwordReset.setUsedState("IN-ACTIVE");
                        repository.save(passwordReset);
                        userRepository.updateUserPassword(user.getEmail(), bCryptPasswordEncoder.encode(request.newPass()));
                        //TODO push lock account notification in case the change was not initiate by the account owner
                        return CustomResponse.builder()
                                .responseCode("200")
                                .responseDesc("Password was successfully updated")
                                .data(passwordResets.getFirst().getRedirectUrl())
                                .build();

                    } else {
                        return CustomResponse.builder()
                                .error(UnsuccessfulResponse.invalid_request)
                                .errorDescription("New password cannot be similar to the old password")
                                .build();
                    }
                } else {
                    return CustomResponse.builder()
                            .error(UnsuccessfulResponse.invalid_request)
                            .errorDescription("Password do not match")
                            .build();
                }
            } else {
                return CustomResponse.builder()
                        .error(UnsuccessfulResponse.invalid_request)
                        .errorDescription("New password doest meet the password strength requirement")
                        .build();
            }
        } else {
            return CustomResponse.builder()
                    .error(UnsuccessfulResponse.invalid_request)
                    .errorDescription("Reset token unavailable or expired")
                    .build();
        }
    }

    public boolean hasConsecutiveSequence(String password, int sequenceLength) {
        if (password == null || password.length() < sequenceLength) {
            return false;
        }

        for (int i = 0; i <= password.length() - sequenceLength; i++) {
            boolean increasing = true;
            boolean decreasing = true;

            for (int j = 0; j < sequenceLength - 1; j++) {
                char current = password.charAt(i + j);
                char next = password.charAt(i + j + 1);

                if (next != current + 1) {
                    increasing = false;
                }
                if (next != current - 1) {
                    decreasing = false;
                }
            }

            if (increasing || decreasing) {
                return true;
            }
        }
        return false;
    }

    public boolean isPasswordContaining(String userFullName, String password) {

        String[] names = userFullName.split(" ");

        for (String name : names) {
            if (password.toLowerCase().contains(name.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
}
