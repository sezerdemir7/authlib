package com.inonu.authlib.annottation;


import com.hazelcast.client.HazelcastClient;
import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.client.config.ClientNetworkConfig;
import com.hazelcast.core.HazelcastInstance;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class HazelcastClientConfig {

    @Bean
    public HazelcastInstance hazelcastClientInstance() {
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.setInstanceName("user-privileges");

        // Cluster'a otomatik bağlanma (Multicast)
        ClientNetworkConfig networkConfig = clientConfig.getNetworkConfig();
        networkConfig.setSmartRouting(true);
        networkConfig.setRedoOperation(true);

        return HazelcastClient.newHazelcastClient(clientConfig);
    }
}

