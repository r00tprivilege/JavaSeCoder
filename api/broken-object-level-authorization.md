# Broken Object Level Authorization

## 1. Intro:

**Broken Object Level Authorization** happens **when an application does not correctly confirm that the user performing the request has the required privileges to access the user they are requesting for**. Since APIs typically expose endpoints that handle some kind of object identifiers\(ids, names, tags, etc\) they allow for a wide attack surface of improper access.

## 2. Typical vulnerable code:

Imagine that this endpoint is used when users want to retrieve their personal secrets. 

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
public class UserController {

    private final UserHandler userHandler;
    private final SecretsHandler secretsHandler;

    public UserController(UserHandler userHandler, SecretsHandler secretsHandler) {
        this.userHandler = userHandler;
        this.secretsHandler = secretsHandler;
    }

    @GetMapping("/api/{userId}/secrets")
    public ResponseEntity<?> getUserSecrets(@PathVariable String userId) {
        User user = userHandler.getUserDetails(userId);
        List<Secret> secrets = secretsHandler.getSecretsByUser(user);

        return ResponseEntity.ok(Map.of(
                "user", user,
                "secrets", secrets
        ));
    }
}

class User {
    // Define your User class fields and methods here
}

class Secret {
    // Define your Secret class fields and methods here
}

class UserHandler {
    public User getUserDetails(String userId) {
        // Implement this method to fetch user details
        return new User();
    }
}

class SecretsHandler {
    public List<Secret> getSecretsByUser(User user) {
        // Implement this method to fetch secrets by user
        return new ArrayList<>();
    }
}

```

## 3. Mitigation:

### 3.1. Access Control:

Implementing a robust access control policy is crucial in this scenario. Instead of allowing arbitrary parameters to query the API, developers should manage sessions. Sessions offer enhanced security and are generally difficult to manipulate, making them the preferred method for securing object referencing endpoints.

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import javax.servlet.http.HttpSession;
import java.util.List;
import java.util.Map;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
public class SecretsController {

    private final UserHandler userHandler;
    private final SecretsHandler secretsHandler;

    public SecretsController(UserHandler userHandler, SecretsHandler secretsHandler) {
        this.userHandler = userHandler;
        this.secretsHandler = secretsHandler;
    }

    @GetMapping("/api/secrets")
    public ResponseEntity<?> getUserSecrets(HttpSession session) {
        String userId = (String) session.getAttribute("userId");
        if (userId == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Unauthorized. You shall not hack!");
        }

        User user = userHandler.getUserDetails(userId);
        List<Secret> secrets = secretsHandler.getSecretsByUser(user);

        return ResponseEntity.ok(Map.of(
                "user", user,
                "secrets", secrets
        ));
    }
}

// Define User, Secret, UserHandler, and SecretsHandler classes similarly as before

class User {
    // Define your User class fields and methods here
}

class Secret {
    // Define your Secret class fields and methods here
}

class UserHandler {
    public User getUserDetails(String userId) {
        // Implement this method to fetch user details
        return new User();
    }
}

class SecretsHandler {
    public List<Secret> getSecretsByUser(User user) {
        // Implement this method to fetch secrets by user
        return new ArrayList<>();
    }
}
```
In this Java Spring Boot version, the SecretsController class handles GET requests to the /api/secrets endpoint. It checks if the userId is present in the session, and if not, it returns a 403 Forbidden status. If the userId is found, it retrieves user details and secrets and returns them in the response. You'll need to implement the logic for the User, Secret, UserHandler, and SecretsHandler classes as needed.

{% hint style="danger" %}
Ensure all HTTP methods for each endpoint are secured. It is a common practice for developers to protect the GET requests on a specific endpoint, but often the DELETE, POST, and PUT requests remain vulnerable.
{% endhint %}

### 3.2. Working without Access Control:

While not ideal, you could implement a "security through obscurity" approach. This involves referencing objects with random and unpredictable values instead of straightforward numeric IDs. However, relying solely on random IDs isn't foolproof protection, as IDs can still be leaked or stolen, despite their difficulty to guess or generate. Example:

`/api/r4138749n11b89761b02039b391327643/secrets/`

## 4. Takeaways:

Establishing a solid access control policy, coupled with flawless session management, can effectively mitigate the majority of **Broken Object Level Authorization** issues.

{% hint style="info" %}
More details:
* [What is Broken Object Level Authorization ](https://www.wallarm.com/what/broken-object-level-authorization)
* [OWASP API SECURITY](https://owasp.org/www-project-api-security/)
{% endhint %}

