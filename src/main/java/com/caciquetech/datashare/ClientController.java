package com.caciquetech.datashare;

import com.caciquetech.datashare.security.SecuredJwtSubjectMatchesClientId;
import io.micronaut.http.annotation.*;
import io.micronaut.http.MediaType;
import io.micronaut.security.annotation.Secured;

import java.util.List;
import java.util.Map;

@Controller("/v1/client/{client_id}")
@Secured( "isAuthenticated()")
@SecuredJwtSubjectMatchesClientId(clientIdPathIndex = 3)
public class ClientController {

    @Get(uri="/shares", produces=MediaType.APPLICATION_JSON)

    public Map<String, Object> getClientShares(@PathVariable String client_id) {
        List<Map<String, Object>> shares = List.of(Map.of("name", "Share A"), Map.of("name", "Share C"));

        return Map.of( "shares", shares);
    }
}
