package com.howtodoinjava.jerseydemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.support.SpringBootServletInitializer;

@SpringBootApplication
public class JerseyDemoApplication extends SpringBootServletInitializer {

	public static void main(String[] args) {
		SpringApplication.run(JerseyDemoApplication.class, args);
	}
}
