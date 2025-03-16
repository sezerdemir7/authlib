package com.inonu.authlib.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.util.List;

@Configuration
public class PermissionCheckerAutoConfiguration {

    @Bean
    @ConditionalOnClass(RedisTemplate.class)
    public RedisTemplate<String, List<String>> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, List<String>> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new ListStringSerializer());
        return template;
    }

    @Bean
    @ConditionalOnClass(RedisTemplate.class)
    public PrivilegeCacheService privilegeCacheService(RedisTemplate<String, List<String>> redisTemplate) {
        return new PrivilegeCacheService(redisTemplate);
    }

    @Bean
    @ConditionalOnClass(RedisTemplate.class)
    public PermissionAspect permissionAspect(PrivilegeCacheService privilegeCacheService) {
        return new PermissionAspect(privilegeCacheService);
    }
}