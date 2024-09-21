package com.sds.authorization.server.service;


import com.sds.authorization.server.utility.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Date;
import java.util.Properties;

/**
 * @author samwel.wafula
 * Created on 07/03/2024
 * Time 10:56
 * Project MoneyTrans
 */

@Service
@Slf4j
@RequiredArgsConstructor
public class EmailNotificationService {

    public String subject = "SDS APP";


    private final AppConfig config;

    public Mono<Object> sendNotification(String msg, String email) {

        final Session newSession = Session.getInstance(this.Mail_Properties(), new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(config.getMailUsername(), config.getMailPassword());
            }
        });

        try {
            String[] recipient = email.split(",");

            InternetAddress[] internetAddresses = new InternetAddress[recipient.length];

            for (int i = 0; i < recipient.length; i++) {
                internetAddresses[i] = new InternetAddress(recipient[i]);
            }

            final Message EmailMessage = new MimeMessage(newSession);
            EmailMessage.addRecipients(Message.RecipientType.TO, internetAddresses);
            EmailMessage.setFrom(new InternetAddress(config.getMailUsername()));
            EmailMessage.setSubject(this.subject); // email subject
            EmailMessage.setContent(msg, "text/html"); // The content of email
            EmailMessage.setSentDate(new Date());
            Transport.send(EmailMessage);// Transport the email
            return Mono.just("Your Email has been sent successfully!");
        } catch (final MessagingException e) { // exception to catch the errors
            log.error("Email Sending Failed"); // failed
            e.getCause();
            return Mono.just("Email not sent for " + email);
        }

    }

    public Properties Mail_Properties() {
        final Properties Mail_Prop = new Properties();
        Mail_Prop.put("mail.smtp.host", config.getMailHost());
        Mail_Prop.put("mail.smtp.post", "587");
        Mail_Prop.put("mail.smtp.auth", true);
        Mail_Prop.put("mail.smtp.starttls.enable", true);
        Mail_Prop.put("mail.smtp.ssl.protocols", "TLSv1.2");
        return Mail_Prop;
    }

    public static String EmailTemplate = """
            <div style="background-color:#e6e6e8; display:grid; justify-content: center; font-family: monospace;">
                <div></div>
                <table style="width:100%%;border-radius: 25px;">
                    <tbody>
                    <tr height="32" style="height:32px">
                        <td></td>
                    </tr>
                    <tr align='center'>
                        <td style="background-color:white;width:100%%;padding:0;border-style:solid none;border-top-width:1pt;border-bottom-width:1pt;border-top-color:#EDEFF2;border-bottom-color:#EDEFF2;box-sizing:border-box;">
                            <div align="center">
                                <table border="0" cellpadding="0" cellspacing="0"
                                       style="background-color:white;width:427.5pt;box-sizing:border-box;">
                                    <tbody>
                                    <tr style="background-color:#7c74cc; font-family: monospace;">
                                        <td style="padding:18.75pt 0;">
                                            <p align="center" style="font-size:11pt; text-align:center;margin:0;">
                                        <span>
                                            <a style="text-decoration:none" data-auth="NotApplicable" data-linkindex="3"
                                               href="https://asgard.slafrica.net:9810/"
                                               rel="noopener noreferrer" target="_blank">
                                                <b><span style="color:#000000;font-size:16.5pt;">Service Delivery Application </span></b>
                                            </a>
                                        </span>
                                            </p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding:26.25pt;box-sizing:border-box;">
                                            <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt; font-size:11pt;">
                                                <span style="color: rgb(61, 72, 82);  ">Hi,</span>
                                            </p>
                                            <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt; font-size:11pt;">
                                                <span style="color: rgb(61, 72, 82); ">Hi %s, <br>Use %s  as your password </br></span>
                                            </p>
                                            <hr/>
                                            <p style="margin-top:0; box-sizing:border-box; text-align: center; font-family: monospace;">
                                                        <span style="color:#03540c; font-size:9pt; text-align: center;">
                                                            This email is intended for the purpose user information activity.</span>
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
                                                            <span style="color:; font-size: 9pt;">©2024 SOCF. All rights reserved.</span>
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
