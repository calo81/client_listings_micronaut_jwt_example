package com.nwboxed;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.*;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.reader.TokenReader;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Singleton
@Filter("/client/**")
public class ClientAuthorisationFilter implements HttpServerFilter {

    private final TokenReader<HttpRequest<?>> tokenReader;
    private final TokenValidator<HttpRequest<?>> tokenValidator;

    public ClientAuthorisationFilter(TokenReader<HttpRequest<?>> tokenReader,
                                     TokenValidator<HttpRequest<?>> tokenValidator) {
        this.tokenReader = tokenReader;
        this.tokenValidator = tokenValidator;
    }

    @Override
    @NonNull
    public Publisher<MutableHttpResponse<?>> doFilter(@NonNull HttpRequest<?> request,
                                                      @NonNull ServerFilterChain chain) {
        String[] segments = request.getPath().split("/");
        if (segments.length < 3) {
            return Mono.just(HttpResponse.badRequest().body("Missing client_id in path"));
        }
        String clientIdInPath = segments[2];

        Optional<String> tokenOpt = tokenReader.findToken(request);

        if (tokenOpt.isEmpty()) {
            return Mono.just(HttpResponse.unauthorized().body("Missing Bearer token"));
        }

        String token = tokenOpt.get();

        return Mono.from(tokenValidator.validateToken(token, request))
                .flatMap(auth -> {

                    Object subObj = auth.getAttributes().get("sub");

                    if (subObj == null || !clientIdInPath.equals(subObj.toString())) {
                        return Mono.just(HttpResponse.status(HttpStatus.FORBIDDEN)
                                .body("Forbidden: sub ≠ client_id"));
                    }

                    return Mono.from(chain.proceed(request));
                });
    }
}