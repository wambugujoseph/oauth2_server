package com.sds.authorization.server.service;


import com.google.common.cache.Cache;
import com.sds.authorization.server.configuration.AppProps;
import com.sds.authorization.server.utility.InMemCache;
import jakarta.mail.Authenticator;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;

/**
 * @author joseph.kibe
 * Created On 11/12/2024 22:39
 **/

@Slf4j
@Service
public class NotificationServiceImpl implements NotificationService {

    private final Cache<String, Object> cache;
    private final AppProps config;

    public NotificationServiceImpl(AppProps props) {
        this.config = props;
        this.cache = new InMemCache().getNotificationCache();
    }

    @Override
    public void sendSmsNotification(String id, String body, String subject, String[] recipient) {

    }

    @Override
    public void sendEmailNotification(String id, String body, String subject, String[] recipient) {

        try {
                /*
                Prevent repeated sending of email by checking whether the notification id is in cache
                Until the notification is expired in the cache based on the set time notification of the said id won't be sent
                */

            if (cache.getIfPresent(id) != null) {
                return;
            }

            body = String.format(EmailTemplate, "", body);
            cache.put(id, body); // Prevent sending the same for the next set expiry time
            final Session newSession = Session.getInstance(this.Mail_Properties(), new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(config.emailUsername(), config.emailPassword());
                }
            });

            MimeMessage EmailMessage = new MimeMessage(newSession);
            MimeMessageHelper emailMessage = new MimeMessageHelper(EmailMessage);

            try {
                emailMessage.setTo(recipient);
                emailMessage.setFrom(new InternetAddress(config.emailUsername()));
                emailMessage.setSubject(subject); // email subject
                emailMessage.setText(body, true); // The content of email
                emailMessage.setSentDate(new Date());
                // Transport the email
                CompletableFuture<String> emailSending = CompletableFuture.supplyAsync(() -> {
                    try {
                        Transport.send(EmailMessage);
                        return "Your Email has been sent successfully!";
                    } catch (Exception e) {
                        log.error(e.getMessage(), e);
                        return "Error sending email " + e.getMessage();
                    }
                });
                emailSending.thenAccept(log::info);

            } catch (Exception e) {
                log.error(e.getMessage());
            }

        } catch (final Exception e) { // exception to catch the errors
            log.error("Email Sending Failed"); // failed
        }
    }

    private Properties Mail_Properties() {
        final Properties Mail_Prop = new Properties();

        Mail_Prop.put("mail.smtp.host", config.smtpHost());
        Mail_Prop.put("mail.smtp.port", config.smtpPort());
        Mail_Prop.put("mail.smtp.auth", true);
        Mail_Prop.put("mail.smtp.starttls.enable", true);
        Mail_Prop.put("mail.smtp.ssl.protocols", "TLSv1.2");

        return Mail_Prop;
    }

    public static String EmailTemplate = """
            <div style="display:grid; justify-content: center;">
                <div></div>
                <table style="width:100%%;border-radius: 25px;">
                    <tbody>
                    <tr height="32" style="height:32px">
                        <td></td>
                    </tr>
                    <tr align='center'>
                        <td style="width:100%%;padding:0;border-style:solid none;border-top-width:1pt;border-bottom-width:1pt;border-top-color:#EDEFF2;border-bottom-color:#EDEFF2;box-sizing:border-box;">
                            <div align="center">
                                <table cellpadding="0" cellspacing="0"
                                       style="background-color:white;width:500.5pt;box-sizing:border-box; border-color:#A0A0A0 #A0A0A0 #ffffff #A0A0A0; border-width:1px">
                                    <tbody>
                                    <tr style="background-color:#7c74cc;">
                                        <td style="padding:18.75pt 0;">
                                            <p align="center" style="font-size:11pt; text-align:center;margin:0;">
                                        <span>
                                            <a style="text-decoration:none" data-auth="NotApplicable" data-linkindex="3"
                                               href="https://asgard.slafrica.net:9810/"
                                               rel="noopener noreferrer" target="_blank">
                                                <b><span style="color:#000000;font-size:16.5pt;">Switch-Bridge</span></b>
                                            </a>
                                        </span>
                                            </p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding:26.25pt;box-sizing:border-box; color: rgb(61, 72, 82); border-width:1px">
                                            <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt; font-size:11pt;">
                                                <span>Hi%s,</span>
                                            </p>
                                            <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt; font-size:11pt;">
                                                <span>%s</span>
                                            </p>
                                            <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt;">
                                            <span style="font-family: &quot;Segoe UI&quot;, sans-serif, serif, EmojiFont;">Kind Regards,<br
                                                    aria-hidden="true">Switch-Bridge</span>
                                            </p>
                                            <p style="margin-top:0; box-sizing:border-box; text-align: center;">
                                                        <span style="color: rgb(174, 174, 174); font-size:9pt; text-align: center;">
                                                           </span>
                                            </p>
                                        </td>
                                    </tr>
                                    <tr align='center'>
                                        <td style="background-color:#cccccc; padding:0;box-sizing:border-box;">
                                            <div align="center">
                                                <table border="0" cellpadding="0" cellspacing="0"
                                                       style="width:427.5pt;box-sizing:border-box;">
                                                    <tbody>
                                                    <tr></tr>
                                                    <td style="padding:10pt;box-sizing:border-box;">
                                                        <p align="center"
                                                           style="text-align:center;margin-top:0;box-sizing:border-box;line-height:18.0pt;">
                                                            <span style="font-family: &quot;Segoe UI&quot;, sans-serif, serif, EmojiFont;">
                                                            ©2024. All rights reserved.</span>
                                                               <hr/>
                                                             CONFIDENTIALITY NOTICE: This message (and any attachment) is confidential and intended for the sole use of the individual or entity to which it 
                                                             is addressed. If you are not the intended recipient, you must not review, retransmit, convert to hard-copy, copy, use or disseminate this email or any of its attachments. If you received this email in error, please notify the sender immediately and delete it. This notice is automatically appended to all Internet email.
                                                            
                                                        </p></td>
                                                    </tr>
                                                    </tbody>
                                                </table>
                                            </div>
                                        </td>
                                    </tr>
                                    </tbody>
                                </table>
                            </div>
                        </td>
                    </tr>
                    <tr height="32" style="height:32px">
                        <td></td>
                    </tr>
                    </tbody>
                </table>
            </div>
            """;
}
