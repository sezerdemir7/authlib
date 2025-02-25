package com.inonu.authlib.service;


import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PrivilegeCacheService{

    private final HazelcastInstance hazelcastInstance;
    private static final Logger logger = LoggerFactory.getLogger(PrivilegeCacheService.class);


    public PrivilegeCacheService(HazelcastInstance hazelcastInstance) {
        this.hazelcastInstance = hazelcastInstance;
    }


    public void cacheUserPrivileges(String userName, List<String> privileges) {
        IMap<String, List<String>> privilegeMap = hazelcastInstance.getMap("user-privileges");
        privilegeMap.put(userName, privileges);
        logger.info("Kullanıcı yetkileri cache'e eklendi: {} -> {}", userName, privileges);
    }


    public List<String> getUserPrivileges(String userName) {
        IMap<String, List<String>> privilegeMap = hazelcastInstance.getMap("user-privileges");
        List<String> privileges = privilegeMap.get(userName);
        logger.info("Kullanıcı yetkileri getirildi: {} -> {}", userName, privileges);
        return privileges;
    }


    public void removeUserPrivileges(String userName) {
        IMap<String, List<String>> privilegeMap = hazelcastInstance.getMap("user-privileges");
        privilegeMap.remove(userName);
        logger.info("Kullanıcının yetkileri cache'ten kaldırıldı: {}", userName);
    }
}
