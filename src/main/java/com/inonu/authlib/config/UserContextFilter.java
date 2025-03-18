package com.inonu.authlib.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class UserContextFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(UserContextFilter.class);
    private static final ThreadLocal<String> userIdHolder = new ThreadLocal<>();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (request instanceof HttpServletRequest httpRequest) {
            String userId = httpRequest.getHeader("userId");

            if (userId != null && !userId.isEmpty()) {
                userIdHolder.set(userId);
                logger.info("UserContextFilter - userId set: {}", userId);
            } else {
                logger.warn("UserContextFilter - userId boş veya null!");
            }
        }

        try {
            chain.doFilter(request, response);
        } finally {
            userIdHolder.remove();
        }
    }

    public static String getUserId() {
        return userIdHolder.get();
    }
}
