package elliott.pope.serversideaclenforcerexample;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.access.annotation.Secured;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Secured("ACL_ENFORCE")
public @interface AuthorizedClients {
    @AliasFor("value")
    String[] clients() default {};

    @AliasFor("clients")
    String[] value() default {};

    boolean allowDynamic() default false;
}
