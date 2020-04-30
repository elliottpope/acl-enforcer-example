package elliott.pope.serversideaclenforcerexample;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AclEnforcerExampleApplicationTests {

	@Autowired
	private MockMvc mvc;

	@Test
	void testGetPrincipal() throws Exception {
		String username = "dynamic";
		mvc.perform(get("/secure-2")
				.with(httpBasic(username, "password")))
		.andExpect(status().isOk())
		.andExpect(content().string(username));

		username = "user-2";
		mvc.perform(get("/secure-2")
				.with(httpBasic(username, "password")))
		.andExpect(status().isOk())
		.andExpect(content().string(username));

		username = "admin";
		mvc.perform(get("/secure-2")
				.with(httpBasic(username, "admin-password")))
		.andExpect(status().isOk())
		.andExpect(content().string(username));

		username = "bad-user";
		mvc.perform(get("/secure-2")
				.with(httpBasic(username, "password")))
				.andExpect(status().isUnauthorized());
	}

}
