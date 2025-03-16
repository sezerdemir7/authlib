package com.inonu.authlib;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@SpringBootApplication
@EnableAspectJAutoProxy
public class AuthlibApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthlibApplication.class, args);
	}

}
