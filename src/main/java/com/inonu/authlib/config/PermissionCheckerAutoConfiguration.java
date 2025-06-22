package com.inonu.authlib.config;

import com.inonu.authlib.service.PrivilegeCacheService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.web.context.request.RequestContextListener;

import java.util.List;

@Configuration
public class PermissionCheckerAutoConfiguration {

    @Bean
    public RedisTemplate<String, List<String>> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, List<String>> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new ListStringSerializer());
        return template;
    }

    @Bean
    public PrivilegeCacheService privilegeCacheService(RedisTemplate<String, List<String>> redisTemplate) {
        return new PrivilegeCacheService(redisTemplate);
    }

    @Bean
    public PermissionAspect permissionAspect(PrivilegeCacheService privilegeCacheService, Environment environment) {
        return new PermissionAspect(privilegeCacheService, environment);
    }

    @Bean
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }


}