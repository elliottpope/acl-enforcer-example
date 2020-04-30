package elliott.pope.serversideaclenforcerexample;

import lombok.Data;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AbstractAclVoter;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component
public class AnnotationBasedWebExpressionVoter extends AbstractAclVoter {

    @Autowired
    private DynamicACLAccessVoter dynamicACLAccessVoter;

    private static final Collection<Class<? extends Annotation>> REQUEST_MAPPINGS = Arrays.asList(
            RequestMapping.class,
            GetMapping.class,
            PostMapping.class,
            DeleteMapping.class,
            PatchMapping.class);

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return "ACL_ENFORCE".equals(attribute.getAttribute());
    }

    @Override
    public int vote(Authentication authentication, MethodInvocation object, Collection<ConfigAttribute> attributes) {
        System.err.println(String.format("Attempted to access method %s with principal %s with attributes %s",
                object.getMethod().getName(),
                authentication.getPrincipal(),
                attributes));
        if (object.getMethod().isAnnotationPresent(AuthorizedClients.class)) {
            for (String client : object.getMethod().getAnnotation(AuthorizedClients.class).value()) {
                if (authentication.getName().matches(compileToRegex(client))) {
                    return ACCESS_GRANTED;
                }
            }
            final Optional<Class<? extends Annotation>> requestMapping =
                    REQUEST_MAPPINGS.stream()
                            .filter(annotation -> object.getMethod().isAnnotationPresent(annotation))
                            .findAny();
            if (requestMapping.isPresent()) {
                final RequestMappings mapping = RequestMappings.fromAnnotation(requestMapping.get());
                final Collection<AclEndpoint> requestedEndpoints = extract(
                        mapping,
                        object.getMethod().getAnnotation(requestMapping.get()),
                        authentication.getName());
                if (requestedEndpoints.stream().anyMatch(endpoint -> dynamicACLAccessVoter.vote(endpoint))) {
                    return ACCESS_GRANTED;
                }
            }
            return ACCESS_DENIED;
        }
        return ACCESS_ABSTAIN;
    }

    private static String compileToRegex(String input) {
        Pattern regex = Pattern.compile("[^*]+|(\\*)");
        Matcher m = regex.matcher(input);
        StringBuffer b = new StringBuffer();
        while (m.find()) {
            if (m.group(1) != null) m.appendReplacement(b, ".*");
            else m.appendReplacement(b, "\\\\Q" + m.group(0) + "\\\\E");
        }
        m.appendTail(b);
        return b.toString();
    }

    private static Collection<AclEndpoint> extract(
            final RequestMappings mapping,
            final Annotation annotation,
            final String client) {
        final String[] paths;
        final String method;
        switch (mapping) {
            case GET -> {
                final GetMapping getMapping = (GetMapping) annotation;
                paths = getMapping.value();
                method = HttpMethod.GET.name();
            }
            case PUT -> {
                final PutMapping putMapping = (PutMapping) annotation;
                paths = putMapping.value();
                method = HttpMethod.PUT.name();
            }
            case DELETE -> {
                final DeleteMapping deleteMapping = (DeleteMapping) annotation;
                paths = deleteMapping.value();
                method = HttpMethod.DELETE.name();
            }
            case PATCH -> {
                final PatchMapping patchMapping = (PatchMapping) annotation;
                paths = patchMapping.value();
                method = HttpMethod.PATCH.name();
            }
            case REQUEST -> {
                final RequestMapping requestMapping = (RequestMapping) annotation;
                paths = requestMapping.value();
                method = requestMapping.method()[0].name();
            }
            default -> {
                paths = new String[]{};
                method = "";
            }
        }

        return Arrays.stream(paths)
                .map(path -> {
                    final AclEndpoint endpoint = new AclEndpoint();
                    endpoint.setEndpoint(path);
                    endpoint.setMethod(method);
                    endpoint.setClient(client);
                    return endpoint;
                })
                .collect(Collectors.toSet());
    }
}

@Data
class AclEndpoint {
    private String method;
    private String endpoint;
    private String client;
}

enum RequestMappings {
    GET(GetMapping.class),
    PUT(PutMapping.class),
    POST(PostMapping.class),
    DELETE(DeleteMapping.class),
    PATCH(PatchMapping.class),
    REQUEST(RequestMapping.class);

    private Class<? extends Annotation> annotation;

    RequestMappings(Class<? extends Annotation> annotation) {
        this.annotation = annotation;
    }

    public static RequestMappings fromAnnotation(Class<? extends Annotation> annotation) {
        for (RequestMappings mapping : RequestMappings.values()) {
            if (mapping.annotation.equals(annotation)) {
                return mapping;
            }
        }
        throw new IllegalArgumentException("No RequestMapping known for annotation type " + annotation);
    }
}

