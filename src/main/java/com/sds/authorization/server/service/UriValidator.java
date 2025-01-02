package com.sds.authorization.server.service;


import lombok.extern.slf4j.Slf4j;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

/**
 * @author joseph.kibe
 * Created On 21/12/2024 20:53
 **/

@Slf4j
public class UriValidator {

    public static String isRedirectUriValid(String providedUrls) {

        try {
            for (String providedUrl : providedUrls.split(",")) {
                URL url = URI.create(providedUrl).toURL();

                if (!url.getProtocol().equalsIgnoreCase("HTTPS")) {
                    return "Invalid redirect Url Protocol. The url should be SSL/TLS  protected";
                }

                if (url.getRef() != null) {
                    return "Fragment components are not allowed on the redirect url";
                }
            }
            return null;

        } catch (MalformedURLException e) {
            log.error(e.getMessage(), e);
        }

        return "Failed to validate the redirect url";
    }

    public static String compareRedirectUrlTOClientRedirect(String redirect, String clientRedirect) {
        try {
            boolean isUrlContained = false;
            URL url = URI.create(redirect).toURL();

            for (String r : clientRedirect.split(",")) {
                URL tempUrl = URI.create(r).toURL();
                if (url.toString().equalsIgnoreCase(tempUrl.toString())) {
                    isUrlContained = true;
                }
            }

            if (!isUrlContained) {
                return "The redirect url provide is invalid, check the client configure url";
            }

            return null;
        } catch (MalformedURLException e) {
            log.error(e.getMessage(), e);
        }

        return "Failed to validate the redirect url";
    }

}
