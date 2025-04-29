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

        String userId = getParameterValueByName(joinPoint, "userId", String.class);
        Long unitId = getParameterValueByName(joinPoint, "unitId", Long.class);
        Long appId = getParameterValueByName(joinPoint, "appId", Long.class);

        if (userId == null || userId.isEmpty() || unitId == null || appId == null) {
            logger.error("Geçersiz yetkilendirme isteği. userId, unitId veya appId eksik!");
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
            String[] requiredRoleExpressions = permission.roles();
            if (requiredRoleExpressions == null || requiredRoleExpressions.length == 0) {
                throw new PrivilegeException("Gerekli roller belirtilmemiş.");
            }

            StandardEvaluationContext context = new StandardEvaluationContext();
            context.setVariable("userId", userId);
            context.setVariable("unitId", unitId);
            context.setVariable("appId", appId);

            boolean hasPermission = Arrays.stream(requiredRoleExpressions)
                    .map(expr -> {
                        String generatedPermission = parser.parseExpression(expr).getValue(context, String.class);
                        logger.info("SpEL tarafından oluşturulan yetki ifadesi: {}", generatedPermission);
                        return generatedPermission;
                    })
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
