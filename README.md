# ACL Enforcer Example

This project is a quick PoC for using annotation driven endpoint security with following features:

- A Spring MVC endpoint can be annotated with `@AuthorizedClients` with the values of the clients that endpoint accepts.
i.e. `@AuthorizedClient({"user-1", "user-2"})`
- The `@AuthorizedClients` annotation allows `*` wildcards such as `user-*`
- The `@AuthorizedClients` annotation should play well with existing Spring Security annotations and configurations including
`@Secured`, `@PreAuthorize`, custom `AccessDecisionManager`s for both `FilterInvocation`s and `MethodInvocations`
- The `@AuthorizedClients` should only operate on already authenticated clients
- For `@AuthorizedClients(allowDynamic = true)`, the voting logic should lookup ACLs from external sources (likely a database of some kind)
and verify the request against that external list
- If the incoming request does not come from an authenticated and authorized source, then the logic contained in that endpoint should not be executed
to avoid side effects from attackers.