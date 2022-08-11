package io.clamos.gateway.config;

import io.clamos.gateway.filter.JwtTokenAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
/*@EnableWebFluxSecurity*/
public class WebFluxSecurityConfig {

    final JwtTokenAuthorizationFilter jwtTokenAuthorizationFilter;

    private static final String[] excludedAuthPages = {
            /*"/auth/login",
            "/signal/**",
            "/pc/file/**",*/

//            "/auth/logout",
//            "/auth/**",
//            "/pc/**",
              "/**",
    };

    @Bean
    public MapReactiveUserDetailsService userDetailsService() {

        String password = "admin";
//        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
//        String encode = bCryptPasswordEncoder.encode(password);
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("admin")
                .password(password)
                .roles("ADMIN")
                .build();

        MapReactiveUserDetailsService mapReactiveUserDetailsService = new MapReactiveUserDetailsService(userDetails);
        return mapReactiveUserDetailsService;
    }

    @Bean
    SecurityWebFilterChain webFluxSecurityFilterChain(ServerHttpSecurity http) {

        http
                .csrf().disable()
                .cors().disable()
                .formLogin().disable()
                .httpBasic().disable()

//                .exceptionHandling(exceptionHandlingSpec -> exceptionHandlingSpec
//                        .authenticationEntryPoint((exchange, ex) -> {
//
//                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//                            return exchange.getResponse().setComplete();
//                        })
//                        .accessDeniedHandler((exchange, denied) -> {
//                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
//                            return exchange.getResponse().setComplete();
//                        })
//                )

                .exceptionHandling()
                .authenticationEntryPoint((exchange, ex) -> Mono.fromRunnable(() -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                }))
                .accessDeniedHandler((exchange, denied) -> Mono.fromRunnable(() -> {
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                }))

                .and()
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())

                .authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .pathMatchers(excludedAuthPages).permitAll()
//                .pathMatchers("/**").hasAnyRole("ADMIN")
                .anyExchange().authenticated()

                .and()
                .addFilterAt(jwtTokenAuthorizationFilter, SecurityWebFiltersOrder.HTTP_BASIC);

        return http.build();
    }
}
