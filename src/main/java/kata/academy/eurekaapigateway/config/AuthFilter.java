package kata.academy.eurekaapigateway.config;

import kata.academy.eurekaapigateway.dto.UserValidateDto;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {

    private final WebClient.Builder webClientBuilder;

    public AuthFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }
            String token = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String[] parts = token.split(" ");
            if (parts.length != 2 || !parts[0].equals("Bearer")) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }
            return webClientBuilder.build()
                    .post()
                    .uri("lb://eureka-auth-service/api/internal/v1/auth/validate?token=" + parts[1])
                    .retrieve().bodyToMono(UserValidateDto.class)
                    .map(dto -> {
                        ServerHttpRequest request = exchange.getRequest();
                        if ((dto.role().equals("ADMIN") && request.getPath().value().contains("/admin"))
                                || (dto.role().equals("USER") && !request.getPath().value().contains("/admin"))) {
                            exchange.getRequest()
                                    .mutate()
                                    .header("userId", String.valueOf(dto.userId()));
                        } else {
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                        }
                        return exchange;
                    }).flatMap(chain::filter);
        });
    }

    public static class Config {
    }
}
