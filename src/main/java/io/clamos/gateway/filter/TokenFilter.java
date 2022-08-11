package io.clamos.gateway.filter;

import io.clamos.gateway.util.JWTUtils;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.function.Consumer;

@RequiredArgsConstructor
@Slf4j
public class TokenFilter implements GlobalFilter, Ordered {

    final JWTUtils jwtUtils;

    /*private Mono<Void> denyAccess(ServerWebExchange exchange) {

        ServerHttpResponse response = exchange.getResponse();
//        response.setStatusCode(HttpStatus.OK);
        response.setStatusCode(HttpStatus.UNAUTHORIZED);

//        response.getHeaders().add("Content-Type", "application/json;charset=UTF-8");

        byte[] bytes = JSON.toJSONBytes(Result.error(resultCode), SerializerFeature.WriteMapNullValue);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);

        return response.writeWith(Mono.just(buffer));
    }*/

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        String authorization = request.getHeaders().getFirst("Authorization");

        if (!StringUtils.hasLength(authorization)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        Claims claims = jwtUtils.parse(authorization.replace("Bearer ", ""));
        if (claims == null) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String userId = String.valueOf(claims.get("id"));
        Consumer<HttpHeaders> headers = httpHeaders -> {
            httpHeaders.add("id", userId);
        };
        request.mutate().headers(headers).build();

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
