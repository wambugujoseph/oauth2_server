package com.sds.authorization.server.service;


/**
 * @author joseph.kibe
 * Created On 11/12/2024 22:25
 **/

public interface NotificationService {


    void sendSmsNotification(String id, String body, String subject, String[] recipient);

    void sendEmailNotification(String id, String body, String subject, String[] recipient);

}
