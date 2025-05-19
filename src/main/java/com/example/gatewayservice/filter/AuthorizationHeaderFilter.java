package com.example.gatewayservice.filter;

import com.example.gatewayservice.exception.TokenException;
import com.example.gatewayservice.jwt.JwtTokenProvider;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final JwtTokenProvider jwtTokenProvider;

    public AuthorizationHeaderFilter(JwtTokenProvider jwtTokenProvider) {
        super(Config.class);
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String authorizationHeader = exchange.getRequest().getHeaders().getFirst(config.headerName);
            if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith(config.granted + " ")) {
                String token = authorizationHeader.substring(config.granted.length() + 1); // Bearer
                try {
                    if (jwtTokenProvider.validateToken(token)) {

                        String path = exchange.getRequest().getURI().getPath();
                        if(path.equals("/auth/logout")){
                            String userId = jwtTokenProvider.getUserId(token);

                            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                    .header("X-User-Id", userId)
                                    .build();

                            // Token is valid, continue to the next filter
                            return chain.filter(exchange.mutate().request(mutatedRequest).build());
                        }

                        return  chain.filter(exchange); // Token is valid, continue to the next filter
                    }
                } catch (TokenException e) {
                    log.error("Token validation error: {}", e.getMessage());
                } catch (Exception e) {
                    log.error("Unexpected error during JWT validation: {}", e.getMessage());
                }
            }
            return unauthorizedResponse(exchange); // Token is not valid, respond with unauthorized
        };
    }

    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String json = "{\"message\": \"Invalid or missing Token\"}";
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    @Getter
    @Setter
    public static class Config {
        private String headerName;      // Authorization
        private String granted;          // Bearer
    }
}
