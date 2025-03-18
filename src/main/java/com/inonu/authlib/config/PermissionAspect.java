package com.inonu.authlib.config;

import com.inonu.authlib.dto.PermissionRequest;
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
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

@Order(Ordered.LOWEST_PRECEDENCE)
@Aspect
@Component
public class PermissionAspect {

    private static final Logger logger = LoggerFactory.getLogger(PermissionAspect.class);
    private final PrivilegeCacheService privilegeCacheService;
    private final ExpressionParser parser = new SpelExpressionParser();

    public PermissionAspect(PrivilegeCacheService privilegeCacheService) {
        this.privilegeCacheService = privilegeCacheService;
    }

    @Pointcut("@annotation(com.inonu.authlib.config.CheckPermission)")
    public void checkPermissionPointcut() {
    }

    @Around("checkPermissionPointcut()")
    public Object checkPermission(ProceedingJoinPoint joinPoint) throws Throwable {
        logger.info("CheckPermission Aspect çalışıyor!");

        // Request parametrelerinden userId ve unitId al
        String userId = getUserIdFromRequestParams(joinPoint);
        Long unitId = getUnitIdFromRequestParams(joinPoint);

        if (userId == null || userId.isEmpty() || unitId == null) {
            logger.error("Geçersiz yetkilendirme isteği. userId veya unitId eksik!");
            throw new PrivilegeNotFoundException("Kullanıcı kimlik doğrulaması mevcut değil.");
        }

        logger.info("Yetki kontrolü yapılan kullanıcı ID: {}, Unit ID: {}", userId, unitId);

        // Hazelcast Cache üzerinden kullanıcının yetkilerini al
        List<String> privileges = privilegeCacheService.getUserPrivileges(userId);
        logger.info("Kullanıcının yetkileri: {}", privileges);

        if (privileges == null || privileges.isEmpty()) {
            throw new PrivilegeNotFoundException("Kullanıcıya ait yetkiler bulunamadı.");
        }

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        CheckPermission permission = method.getAnnotation(CheckPermission.class);

        if (permission != null) {
            String[] requiredRoleExpressions = permission.roles();
            if (requiredRoleExpressions == null || requiredRoleExpressions.length == 0) {
                throw new PrivilegeException("Gerekli roller belirtilmemiş.");
            }

            // SpEL context ile method parametrelerini ayarla
            StandardEvaluationContext context = new StandardEvaluationContext();
            context.setVariable("userId", userId);
            context.setVariable("unitId", unitId);

            boolean hasPermission = Arrays.stream(requiredRoleExpressions)
                    .map(expr -> parser.parseExpression(expr).getValue(context, String.class))
                    .anyMatch(privileges::contains);

            if (!hasPermission) {
                throw new PrivilegeException("Yetkilendirme hatası: Gerekli yetkilere sahip değilsiniz!");
            }
        }

        logger.info("Yetkilendirme başarılı.");
        return joinPoint.proceed();
    }

    private String getUserIdFromRequestParams(ProceedingJoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        for (Object arg : args) {
            if (arg instanceof String) {
                return (String) arg;  // userId'yi al
            }
        }
        return null;
    }

    private Long getUnitIdFromRequestParams(ProceedingJoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        for (Object arg : args) {
            if (arg instanceof Long) {
                return (Long) arg;  // unitId'yi al
            }
        }
        return null;
    }

}
