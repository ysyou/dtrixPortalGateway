package io.clamos.gateway.filter;

import io.clamos.gateway.util.JWTUtils;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.function.Consumer;

@RequiredArgsConstructor
@Slf4j
@Component
public class JwtTokenAuthorizationFilter implements WebFilter {

    final JWTUtils jwtUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        String authorization = request.getHeaders().getFirst("Authorization");

        String TOKEN_PREFIX = "Bearer ";
        if (StringUtils.hasText(authorization) && authorization.startsWith(TOKEN_PREFIX)) {

            String token = authorization.replace(TOKEN_PREFIX, "");
            Claims claims = jwtUtils.parse(token);
            if (claims != null) {

                // TODO: 05-19 token password update date check

                String userId = String.valueOf(claims.get("id"));
                Consumer<HttpHeaders> headers = httpHeaders -> {
//                    httpHeaders.add("id", userId);
                    httpHeaders.set("id", userId);
                };
                request.mutate().headers(headers).build();

//                Collection<? extends GrantedAuthority> authorities = authoritiesClaim == null ? AuthorityUtils.NO_AUTHORITIES : AuthorityUtils.commaSeparatedStringToAuthorityList(authoritiesClaim.toString());
                Collection<? extends GrantedAuthority> authorities = AuthorityUtils.NO_AUTHORITIES;

                User principal = new User(claims.getSubject(), "", authorities);
                Authentication authentication = new UsernamePasswordAuthenticationToken(principal, token, authorities);

                return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
            }

        }

        return chain.filter(exchange);
    }
}
