package com.jobexecution.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = {"com.persistence", "com.jobexecution.security", "com.jobexecution.controller", "com.jobexecution.service"})
@EnableAutoConfiguration
@EntityScan(basePackages = "com.persistence.model")
@EnableJpaRepositories(basePackages = "com.persistence.repository")
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
}