package com.inonu.authlib.service;


import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

@Service
public class PrivilegeCacheService {
    private static final Logger logger = LoggerFactory.getLogger(PrivilegeCacheService.class);
    private final RedisTemplate<String, List<String>> redisTemplate;

    public PrivilegeCacheService(RedisTemplate<String, List<String>> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public List<String> getUserPrivileges(String userId) {
        List<String> privileges = redisTemplate.opsForValue().get(userId);
        logger.info("Kullanıcı yetkileri Redis'ten getirildi: {} -> {}", userId, privileges);
        return privileges;
    }
}