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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
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

        // userId sadece header'dan alınır
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        String userId = request != null ? request.getHeader("userId") : null;

        // unitId: Önce RequestParam, sonra PathVariable, en son RequestBody'den alınır
        Long unitId = getUnitIdFromRequestParam(joinPoint);
        if (unitId == null) {
            unitId = getUnitIdFromPathVariable(joinPoint);
        }
        if (unitId == null) {
            unitId = getUnitIdFromRequestBody(joinPoint);
        }

        // appId application.properties'ten (ör: app.id=1)
        String appIdProp = environment != null ? environment.getProperty("app.id") : null;
        Long appId = null;
        if (appIdProp != null) {
            try { appId = Long.valueOf(appIdProp); } catch (NumberFormatException ignored) {}
        }

        // Eksik olan alanları logla
        boolean userIdMissing = (userId == null || userId.isEmpty());
        boolean unitIdMissing = (unitId == null);
        boolean appIdMissing = (appId == null);

        if (userIdMissing || unitIdMissing || appIdMissing) {
            logger.error(
                    "Geçersiz yetkilendirme isteği! Eksik alanlar: {}{}{}. " +
                            "[userId headerdan: '{}'] " +
                            "[unitId param/annotation/body: '{}'] " +
                            "[appId property: '{}']",
                    userIdMissing ? "userId " : "",
                    unitIdMissing ? "unitId " : "",
                    appIdMissing ? "appId" : "",
                    userId, unitId, appIdProp
            );
            throw new PrivilegeNotFoundException(
                    "Kullanıcı kimlik doğrulaması mevcut değil. Eksik alan(lar): " +
                            (userIdMissing ? "userId " : "") +
                            (unitIdMissing ? "unitId " : "") +
                            (appIdMissing ? "appId" : "")
            );
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

    // RequestParam ile işaretlenmiş unitId parametresini bul
    private Long getUnitIdFromRequestParam(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Annotation[][] paramAnnotations = method.getParameterAnnotations();
        Object[] args = joinPoint.getArgs();

        for (int i = 0; i < paramAnnotations.length; i++) {
            for (Annotation annotation : paramAnnotations[i]) {
                if (annotation instanceof RequestParam) {
                    RequestParam requestParam = (RequestParam) annotation;
                    if ("unitId".equals(requestParam.value()) || "unitId".equals(requestParam.name())) {
                        Object arg = args[i];
                        if (arg instanceof Long) return (Long) arg;
                        if (arg instanceof String) {
                            try { return Long.valueOf((String) arg); } catch (NumberFormatException ignored) {}
                        }
                    }
                }
            }
        }
        return null;
    }

    // PathVariable ile işaretlenmiş unitId parametresini bul
    private Long getUnitIdFromPathVariable(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Annotation[][] paramAnnotations = method.getParameterAnnotations();
        Object[] args = joinPoint.getArgs();

        for (int i = 0; i < paramAnnotations.length; i++) {
            for (Annotation annotation : paramAnnotations[i]) {
                if (annotation instanceof PathVariable) {
                    PathVariable pathVariable = (PathVariable) annotation;
                    if ("unitId".equals(pathVariable.value()) || "unitId".equals(pathVariable.name())) {
                        Object arg = args[i];
                        if (arg instanceof Long) return (Long) arg;
                        if (arg instanceof String) {
                            try { return Long.valueOf((String) arg); } catch (NumberFormatException ignored) {}
                        }
                    }
                }
            }
        }
        return null;
    }

    // RequestBody içindeki unitId alanını bul
    private Long getUnitIdFromRequestBody(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Annotation[][] paramAnnotations = method.getParameterAnnotations();
        Object[] args = joinPoint.getArgs();

        for (int i = 0; i < paramAnnotations.length; i++) {
            for (Annotation annotation : paramAnnotations[i]) {
                if (annotation instanceof RequestBody && args[i] != null) {
                    Object requestBody = args[i];
                    try {
                        Field field = requestBody.getClass().getDeclaredField("unitId");
                        field.setAccessible(true);
                        Object value = field.get(requestBody);
                        if (value instanceof Long) return (Long) value;
                        if (value instanceof String) {
                            try { return Long.valueOf((String) value); } catch (NumberFormatException ignored) {}
                        }
                    } catch (NoSuchFieldException | IllegalAccessException ignored) {}
                }
            }
        }
        return null;
    }
}