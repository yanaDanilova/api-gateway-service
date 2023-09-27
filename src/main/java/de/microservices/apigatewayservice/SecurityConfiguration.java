package de.microservices.apigatewayservice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;
@EnableWebFluxSecurity
@Configuration
public class SecurityConfiguration {

    private final JwtAuthSecurityFilter jwtAuthSecurityFilter;
    @Autowired
    public SecurityConfiguration(JwtAuthSecurityFilter jwtAuthSecurityFilter) {
        this.jwtAuthSecurityFilter = jwtAuthSecurityFilter;

    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager() {
        return authentication -> Mono.empty();
    }

    @Bean
    SecurityWebFilterChain webFluxSecurityFilterChain(ServerHttpSecurity http) {
        http.csrf(csrf -> csrf.disable())
                .authorizeExchange()
                .pathMatchers("/files").authenticated()
                .anyExchange().permitAll()
                .and()
                .addFilterAt(jwtAuthSecurityFilter,SecurityWebFiltersOrder.AUTHENTICATION);
        return http.build();
    }




}