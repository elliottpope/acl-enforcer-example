package elliott.pope.serversideaclenforcerexample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class AnnotationBasedGlobalMethodSecurity extends GlobalMethodSecurityConfiguration {

    @Autowired
    private AnnotationBasedWebExpressionVoter annotationBasedWebExpressionVoter;

    @Override
    protected AccessDecisionManager accessDecisionManager() {
        final AffirmativeBased accessDecisionManager = ((AffirmativeBased) super.accessDecisionManager());
        accessDecisionManager.getDecisionVoters().add(annotationBasedWebExpressionVoter);
        return accessDecisionManager;
    }

    @Bean
    public DynamicACLAccessVoter dynamicACLAccessVoter() {
        return endpoint -> endpoint.getClient().equals("dynamic") &&
                endpoint.getEndpoint().equals("/secure-2") &&
                endpoint.getMethod().equals("GET");
    }
}
