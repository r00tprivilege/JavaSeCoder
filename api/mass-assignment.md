# Mass Assignment

## 1. Intro:

Modern frameworks often promote the use of functions that automatically bind client input to code variables and internal objects. While this simplifies coding, it doesn't necessarily ensure safety. Binding client-provided data (such as JSON) directly to data models without proper filtering based on an allowlist can result in Mass Assignment vulnerabilities. Attackers can exploit this by guessing object properties (e.g., `admin: true`, `role: admin`), exploring other API endpoints, reading documentation, or adding extra object properties in request payloads to modify object properties they shouldn't have access to.

You can read more about Mass Assignment, with an attacker's perspective, [here](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html).

## 2. Vulnerable Code:

In a typical vulnerable scenario, the developer fails to specify which parts of the object should be updated through the request. Consider the following code example:

```java
const express = require('express');
const app = express();
const router = app.router;

const UserManager = require('UserManager');

/*

for example imagine that schema of the User object looks like:

{
    "uid": String,
    "email": String,
    "password": String,
    "username": String,
    "role": String
}

*/

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserManager userManager;

    public UserController(UserManager userManager) {
        this.userManager = userManager;
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestHeader("Authorization") String token, @RequestBody User user) {
        boolean isValid = userManager.validateToken(token);

        if (isValid) {
            userManager.updateUserSettings(user);
            return ResponseEntity.ok().build();
        } else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Unauthorized");
        }
    }
}

class User {
    private String uid;
    private String email;
    private String password;
    private String username;
    private String role;

    // Getters and setters
}

class UserManager {
    public boolean validateToken(String token) {
        // Implement token validation logic here
        return true;
    }

    public void updateUserSettings(User user) {
        // Implement user settings update logic here
    }
}

```

And the request would look something like this:

```http
POST /api/reset-password

.....

{
    "user": {
        "password": "new_password"
    }
}
```

Because the developer hasn't specified which account fields should be updated, it's possible to input ANY field (provided we know or can guess them) and thus update all those fields. For example, with the request:

```text
POST /api/reset-password

.....

{
    "user": {
        "password": "new_password",
        "role": "admin"
    }
}
```

An attacker successfully updates `role` into `admin`, it means; privileges escalatiion. 

This example represents a common attack scenario, and it's evident that there are numerous other ways to exploit this vulnerability (such as altering another user's password, email, username, etc.).
## 3. Mitigations:

To safeguard against such vulnerabilities in a Spring Boot application with an Oracle database, it is essential to use a schema validation framework and carefully control which fields are updated. Here's how you can approach this:

Best Practice: Implement schema validation and explicitly handle the fields you want to update. Use frameworks like Bean Validation (JSR 380) for schema validation and ensure updates are specific to certain fields.

1. **Entity Class (User.java)**

```java
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;

@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private String uid;
    private String email;
    private String password;
    private String username;
    private String role;

    // Getters and setters
}
```

2. **Controller Class (UserController.java)**

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import javax.servlet.http.HttpSession;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(HttpSession session, @RequestBody PasswordResetRequest request) {
        String userId = (String) session.getAttribute("user_id");

        if (userId == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Unauthorized");
        }

        userService.updateUserPassword(userId, request.getNewPassword());
        return ResponseEntity.ok().build();
    }
}
```

3. **Password Reset Request Class (PasswordResetRequest.java)**

```java
public class PasswordResetRequest {
    private String newPassword;

    // Getter and setter
    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
```

4. **Service Class (UserService.java)**

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Transactional
    public void updateUserPassword(String userId, String newPassword) {
        User user = userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException("User not found"));
        user.setPassword(newPassword);
        userRepository.save(user);
    }
}
```

5. **Repository Interface (UserRepository.java)**

```java
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, String> {
}
```

6. **Exception Class (UserNotFoundException.java)**

```java
public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String message) {
        super(message);
    }
}
```

In this Spring Boot implementation:
- The `User` entity defines the user schema.
- The `UserController` handles the `/reset-password` endpoint, checking for a valid session before updating the password.
- The `PasswordResetRequest` class captures the new password from the request body.
- The `UserService` contains the logic to update the user's password.
- The `UserRepository` interacts with the Oracle database.
- The `UserNotFoundException` handles cases where the user is not found.

## 4. Takeaways:

Following these essential points will defend your endpoints against Mass Assignment:

* Explicitly bind only the specific fields you intend to update from the request.
* Approach framework methods with caution and ensure you thoroughly understand their documentation.
* Clearly define and enforce all expected schemas and data types at both design and runtime stages.

for more details :
* [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
* [Mass Assignment](https://raw.githubusercontent.com/OWASP/API-Security/master/2019/en/dist/owasp-api-security-top-10.pdf)
* [Mass Assignment Application Security](https://application.security/free-application-security-training/owasp-top-10-api-mass-assignment)

