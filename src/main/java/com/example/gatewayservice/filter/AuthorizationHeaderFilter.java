package com.example.gatewayservice.filter;

import com.example.gatewayservice.exception.TokenException;
import com.example.gatewayservice.jwt.JwtTokenProvider;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
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
// 커스텀 필터를 만들기 위해서 AbstractGatewayFilterFactory를 상속
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final JwtTokenProvider jwtTokenProvider;

    public AuthorizationHeaderFilter(JwtTokenProvider jwtTokenProvider) {

        super(Config.class);
        this.jwtTokenProvider = jwtTokenProvider;
    }

    // 라우트 정의 시 해당 필터가 어떻게 동작할지 정의
    // config는 application.yml의 args: 부분에서 받은 값
    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {

            // 1) CORS preflight는 무조건 통과
            if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
                return chain.filter(exchange);
            }


            // 2) Authorization 헤더 검사
            // 헤더값 추출. config.headerName에 Authorization이라면 해당 헤더 값을 읽어온다.
            String authorizationHeader = exchange.getRequest().getHeaders().getFirst(config.headerName);

            if(!StringUtils.hasText(authorizationHeader) || !authorizationHeader.startsWith(config.granted + " ")){
                return unauthorizedResponse(exchange);
            }

            String token = authorizationHeader.substring((config.granted + " ").length());

            try {
                // 3) 토큰 검증
                if (!jwtTokenProvider.validateToken(token)) {
                    return unauthorizedResponse(exchange);
                }

                // 4) 토큰에서 userId 추출 후 항상 주입(덮어쓰기)
                String userId = jwtTokenProvider.getUserId(token);
                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .headers(h -> {
                            // 클라이언트가 보낸 값이 있어도 게이트웨이가 덮어씀
                            h.set("X-User-Id", userId);
                            // 필요하면 access token도 정리 가능: h.remove(HttpHeaders.AUTHORIZATION);
                        })
                        .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());

            } catch (TokenException e) {
                log.error("Token validation error: {}", e.getMessage());
                return unauthorizedResponse(exchange);
            } catch (Exception e) {
                log.error("Unexpected error during JWT validation: {}", e.getMessage());
                return unauthorizedResponse(exchange);
            }

//            // 헤더값이 존재하고, Bearer로 시작하는지 확인
//            if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith(config.granted + " ")) {
//
//                // Bearer 다음에 오는 토큰을 추출
//                String token = authorizationHeader.substring(config.granted.length() + 1); // Bearer
//
//                try {
//                    // 토큰이 유효한지 검증
//                    if (jwtTokenProvider.validateToken(token)) {
//
//                        // 요청 경로 확인
//                        String path = exchange.getRequest().getURI().getPath();
//
//                        // 로그아웃 경로인 경우 userId를 헤더에 추가
//                        if(path.equals("/auth/logout")){
//                            // 토큰에서 userId를 추출
//                            String userId = jwtTokenProvider.getUserId(token);
//
//                            // 기존 요청에 X-User-Id 헤더를 덧붙여 downstream 서비스(auth-service 등)로 전달
//                            // Spring Cloud Gateway에서는 ServerHttpRequest를 mutate() 로 복사/변경해야만 해더를 조작할 수 있다.
//                            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
//                                    .header("X-User-Id", userId)
//                                    .build();
//
//                            //  변경된 요청으로 필터 체인 계속 진행
//                            return chain.filter(exchange.mutate().request(mutatedRequest).build());
//                        }
//
//                        return  chain.filter(exchange); // Token is valid, continue to the next filter
//                    }
//                } catch (TokenException e) {
//                    log.error("Token validation error: {}", e.getMessage());
//                } catch (Exception e) {
//                    log.error("Unexpected error during JWT validation: {}", e.getMessage());
//                }
//            }
//            return unauthorizedResponse(exchange); // Token is not valid, respond with unauthorized
        };
    }

    // 인증실패시 호출 메서드
    // 401 Unauthorized 응답을 JSON 응답 본문과 함께 반환
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
    // 필터에서 사용하는 설정값을 외부 application.yml 등에서 주입받기 위한 클래스
    // args: 로 전달된 값을 이 클래스에 매핑
    public static class Config {
        private String headerName;      // Authorization
        private String granted;          // Bearer
    }
}
