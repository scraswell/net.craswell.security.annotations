package net.craswell.security.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotates a class to indicate that some or all fields must be secured.
 * 
 * @author scraswell@gmail.com
 *
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.CLASS)
public @interface RequiresConfidentiality {
}