package elliott.pope.serversideaclenforcerexample;

@FunctionalInterface
public interface DynamicACLAccessVoter {
    boolean vote(AclEndpoint endpoint);
}
