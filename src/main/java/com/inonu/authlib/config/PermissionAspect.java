package com.inonu.authlib.config;



import com.inonu.authlib.exception.PrivilegeException;
import com.inonu.authlib.exception.PrivilegeNotFoundException;
import com.inonu.authlib.service.PrivilegeCacheService;
import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

@Order(Ordered.LOWEST_PRECEDENCE)
@Aspect
@Component
public class PermissionAspect {

    private static final Logger logger = LoggerFactory.getLogger(PermissionAspect.class);
    private final PrivilegeCacheService privilegeCacheService;
    private final HttpServletRequest request;  // Doğrudan enjekte ediliyor
    private final ExpressionParser parser = new SpelExpressionParser();

    public PermissionAspect(PrivilegeCacheService privilegeCacheService, HttpServletRequest request) {
        this.privilegeCacheService = privilegeCacheService;
        this.request = request;
    }

    @Pointcut("@annotation(com.inonu.authlib.config.CheckPermission)")
    public void checkPermissionPointcut() {
    }

    @Around("checkPermissionPointcut()")
    public Object checkPermission(ProceedingJoinPoint joinPoint) throws Throwable {
        logger.info("CheckPermission Aspect çalışıyor!");

        // Request'ten userId'yi al
        String userId = getUserIdFromHeader();
        if (userId == null || userId.isEmpty()) {
            logger.info("userId=null veya boş!");
            throw new PrivilegeNotFoundException("Kullanıcı kimlik doğrulaması mevcut değil.");
        }

        logger.info("Yetki kontrolü yapılan kullanıcı ID: {}", userId);

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
            String[] parameterNames = signature.getParameterNames();
            Object[] args = joinPoint.getArgs();
            if (parameterNames != null) {
                for (int i = 0; i < parameterNames.length; i++) {
                    context.setVariable(parameterNames[i], args[i]);
                }
            }

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

    private String getUserIdFromHeader() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        String userId = UserContextFilter.getUserId();
        if (userId == null || userId.isEmpty()) {
            logger.error("UserContextFilter ile alınan userId=null veya boş!");
            return null;
        }

        return userId;
    }


}
