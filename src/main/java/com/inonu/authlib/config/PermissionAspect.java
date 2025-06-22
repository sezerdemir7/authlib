package com.inonu.authlib.config;

import com.inonu.authlib.exception.PrivilegeException;
import com.inonu.authlib.exception.PrivilegeNotFoundException;
import com.inonu.authlib.service.PrivilegeCacheService;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

@Order(Ordered.LOWEST_PRECEDENCE)
@Aspect
@Component
public class PermissionAspect {

    private static final Logger logger = LoggerFactory.getLogger(PermissionAspect.class);
    private final PrivilegeCacheService privilegeCacheService;
    private final Environment environment;

    @Autowired
    public PermissionAspect(PrivilegeCacheService privilegeCacheService, Environment environment) {
        this.privilegeCacheService = privilegeCacheService;
        this.environment = environment;
    }

    @Pointcut("@annotation(com.inonu.authlib.config.CheckPermission)")
    public void checkPermissionPointcut() {
    }

    @Around("checkPermissionPointcut()")
    public Object checkPermission(ProceedingJoinPoint joinPoint) throws Throwable {
        logger.info("CheckPermission Aspect çalışıyor!");

        // userId ve unitId önce parametrelerden, yoksa headerdan
        String userId = getParameterValueByName(joinPoint, "userId", String.class);
        Long unitId = getParameterValueByName(joinPoint, "unitId", Long.class);

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        if ((userId == null || userId.isEmpty()) && request.getHeader("userId") != null) {
            userId = request.getHeader("userId");
        }
        if (unitId == null && request.getHeader("unitId") != null) {
            try {
                unitId = Long.valueOf(request.getHeader("unitId"));
            } catch (NumberFormatException ignored) {}
        }

        // appId application.properties'ten (ör: app.id=1)
        Long appId = null;
        try {
            appId = Long.valueOf(environment.getProperty("app.id"));
        } catch (Exception ignored) {}

        if (userId == null || userId.isEmpty() || unitId == null || appId == null) {
            logger.error("Geçersiz yetkilendirme isteği. userId, unitId veya appId eksik!"+userId +"-"+unitId+"-"+"-"+appId);
            throw new PrivilegeNotFoundException("Kullanıcı kimlik doğrulaması mevcut değil.");
        }

        logger.info("Yetki kontrolü yapılan kullanıcı ID: {}, App ID: {}, Unit ID: {}", userId, appId, unitId);

        List<String> privileges = privilegeCacheService.getUserPrivileges(userId);
        logger.info("Kullanıcının yetkileri: {}", privileges);

        if (privileges == null || privileges.isEmpty()) {
            throw new PrivilegeNotFoundException("Kullanıcıya ait yetkiler bulunamadı.");
        }

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        CheckPermission permission = method.getAnnotation(CheckPermission.class);

        if (permission != null) {
            String[] roleSuffixes = permission.roles();
            if (roleSuffixes == null || roleSuffixes.length == 0) {
                throw new PrivilegeException("Gerekli roller belirtilmemiş.");
            }
            final Long finalAppId = appId;
            final Long finalUnitId = unitId;

            boolean hasPermission = Arrays.stream(roleSuffixes)
                    .map(suffix -> "APP" + finalAppId + "_UNIT" + finalUnitId + suffix)
                    .peek(fullRole -> logger.info("Oluşan yetki ifadesi: {}", fullRole))
                    .anyMatch(privileges::contains);

            if (!hasPermission) {
                throw new PrivilegeException("Yetkilendirme hatası: Gerekli yetkilere sahip değilsiniz!");
            }
        }

        logger.info("Yetkilendirme başarılı.");
        return joinPoint.proceed();
    }

    private <T> T getParameterValueByName(ProceedingJoinPoint joinPoint, String name, Class<T> clazz) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] paramNames = signature.getParameterNames();
        Object[] args = joinPoint.getArgs();

        for (int i = 0; i < paramNames.length; i++) {
            if (paramNames[i].equals(name) && clazz.isInstance(args[i])) {
                return clazz.cast(args[i]);
            }
        }
        return null;
    }
}