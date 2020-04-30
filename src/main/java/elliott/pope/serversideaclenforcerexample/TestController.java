package elliott.pope.serversideaclenforcerexample;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class TestController {

    @GetMapping({
            "/secure",
            "/secure-2"
    })
    @AuthorizedClients({
            "user",
            "user-*"})
    @Secured("ROLE_ADMIN")
    public String getPrincipal(Principal principal) {
        System.err.println("getPrincipal was called");
        return principal.getName();
    }
}
