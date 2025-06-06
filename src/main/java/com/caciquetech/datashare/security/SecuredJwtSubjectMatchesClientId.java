package com.caciquetech.datashare.security;

import java.lang.annotation.*;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface SecuredJwtSubjectMatchesClientId {
    int clientIdPathIndex ();
}
