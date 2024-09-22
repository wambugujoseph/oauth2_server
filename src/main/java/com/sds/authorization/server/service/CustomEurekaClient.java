package com.sds.authorization.server.service;

import com.netflix.appinfo.ApplicationInfoManager;
import com.netflix.appinfo.InstanceInfo;
import com.netflix.discovery.DiscoveryClient;
import com.netflix.discovery.EurekaClientConfig;
import com.netflix.discovery.shared.transport.jersey.TransportClientFactories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Timer;
import java.util.TimerTask;


public class CustomEurekaClient extends DiscoveryClient {
    private static final Logger log = LoggerFactory.getLogger(CustomEurekaClient.class);
    private static final long INITIAL_HEARTBEAT_INTERVAL = 30_000; // 30 seconds
    private static final long MAX_HEARTBEAT_INTERVAL = 300_000; // 5 minutes
    private long heartbeatInterval = INITIAL_HEARTBEAT_INTERVAL;
    private Timer heartbeatTimer;
    private final ApplicationInfoManager applicationInfoManager;

    public CustomEurekaClient(ApplicationInfoManager applicationInfoManager, EurekaClientConfig clientConfig, TransportClientFactories transportClientFactories) {
        super(applicationInfoManager, clientConfig, transportClientFactories);
        this.applicationInfoManager = applicationInfoManager; // Store the reference
        startHeartbeatTask();
    }

    private void startHeartbeatTask() {
        heartbeatTimer = new Timer(true);
        heartbeatTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                try {
                    // Update the instance status
                    updateInstanceInfo();
                    heartbeatInterval = INITIAL_HEARTBEAT_INTERVAL;
                } catch (Exception e) {
                    log.error("Heartbeat failed: " + e.getMessage(), e);
                    increaseHeartbeatInterval();
                }
            }
        }, 0, heartbeatInterval);
    }

    private void updateInstanceInfo() {
        // Get the current instance info
        InstanceInfo instanceInfo = applicationInfoManager.getInfo();
        // Set the status to UP
        instanceInfo.setStatus(InstanceInfo.InstanceStatus.UP);

        // Register the updated instance info
        //applicationInfoManager.registerAppMetadata(instanceInfo.getAppName(), instanceInfo.getMetadata());
    }

    private void increaseHeartbeatInterval() {
        heartbeatInterval = Math.min(heartbeatInterval * 2, MAX_HEARTBEAT_INTERVAL);
        log.info("Increased heartbeat interval to {} ms", heartbeatInterval);
        heartbeatTimer.cancel();
        startHeartbeatTask();
    }

    public void shutdown() {
        heartbeatTimer.cancel();
    }
}



