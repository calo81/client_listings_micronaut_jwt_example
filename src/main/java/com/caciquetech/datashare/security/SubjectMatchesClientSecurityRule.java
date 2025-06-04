package com.caciquetech.datashare.security;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpAttributes;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.inject.annotation.EvaluatedAnnotationValue;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.AbstractSecurityRule;
import io.micronaut.security.rules.ConfigurationInterceptUrlMapRule;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.security.token.reader.TokenReader;
import io.micronaut.security.token.validator.TokenValidator;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

@Requires(classes = {HttpRequest.class})
@Singleton
public class SubjectMatchesClientSecurityRule extends AbstractSecurityRule<HttpRequest<?>> {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = ConfigurationInterceptUrlMapRule.ORDER - 100;

    @Inject
    private TokenReader<HttpRequest<?>> tokenReader;
    @Inject
    private TokenValidator<HttpRequest<?>> tokenValidator;

    /**
     * @param rolesFinder Roles Parser
     */

    public SubjectMatchesClientSecurityRule(RolesFinder rolesFinder) {
        super(rolesFinder);
    }

    /**
     * Returns {@link SecurityRuleResult#UNKNOWN} if the {@link Secured} annotation is not
     * found on the method or class, or if the route match is not method based.
     *
     * @param request        The current request
     * @param authentication The authentication, or null if none found
     * @return The result
     */


    @Override
    public Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable Authentication authentication) {
        RouteMatch<?> routeMatch = request.getAttribute(HttpAttributes.ROUTE_MATCH, RouteMatch.class).orElse(null);
        if (routeMatch instanceof MethodBasedRouteMatch) {
            MethodBasedRouteMatch<?, ?> methodRoute = ((MethodBasedRouteMatch) routeMatch);
            AnnotationValue<SecuredJwtSubjectMatchesClientId> securedAnnotation = methodRoute.getAnnotation(SecuredJwtSubjectMatchesClientId.class);
            if (securedAnnotation != null) {
                OptionalInt optionalValue = methodRoute.intValue(SecuredJwtSubjectMatchesClientId.class, "clientIdPathIndex");
                if (optionalValue.isPresent()) {
                    String[] segments = request.getPath().split("/");
                    String clientIdInPath = segments[optionalValue.getAsInt()];

                    Optional<String> tokenOpt = tokenReader.findToken(request);

                    if (tokenOpt.isEmpty()) {
                        return Mono.just(SecurityRuleResult.REJECTED);
                    }

                    String token = tokenOpt.get();

                    return Mono.from(tokenValidator.validateToken(token, request))
                            .flatMap(auth -> {

                                Object subObj = auth.getAttributes().get("sub");

                                if (subObj == null || !clientIdInPath.equals(subObj.toString())) {
                                    return Mono.just(SecurityRuleResult.REJECTED);
                                }

                                return Mono.just(SecurityRuleResult.ALLOWED);
                            });
                }
            }
        }
        return Mono.just(SecurityRuleResult.UNKNOWN);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}

