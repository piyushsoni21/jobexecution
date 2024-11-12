package com.persistence.config;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

@Configuration
public class PostgresConfig {
    // jobexecution DataSource Configuration
    @Bean(value = "jobexecutionDataSource", destroyMethod = "close")
    @Primary
    @ConfigurationProperties(prefix = "jobexecution.datasource")
    public DataSource jobexecutionDataSource() {
        return new HikariDataSource();
    }

    @Bean("jobexecutionJdbcTemplate")
    public JdbcTemplate jobexecutionJdbcTemplate(@Qualifier("jobexecutionDataSource") DataSource scoutDataSource) {
        return new JdbcTemplate(scoutDataSource);
    }
}
