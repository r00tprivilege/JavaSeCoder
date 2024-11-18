# Excessive Data Exposure

## 1. Intro:

This vulnerability occurs when an API depends on clients for **data filtering**. Since APIs are often perceived as **data sources**, developers may implement them in a **generic way** without considering the **sensitivity of the data being exposed**. It is crucial to reveal **only specific details of your data**, even in **error messages**, to minimize the risk of **unintentional data exposure**.

## 2. Vulnerable Code:

In this `forgot-password` scenario, the developer sends the whole `resetData` information to the client.

```java
/*
for example if the reset data is like this:
resetData: {
    "resetToken": "59f3efe43ad4cdc8b8cfc0927a3d4147",
    "email": "bobi@bob.io",
    "lastLoggedIn": "25.03.1919",
    ...
}
*/
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import javax.validation.Valid;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
public class PasswordController {

    private final EmailService emailService;
    private final UserService userService;

    public PasswordController(EmailService emailService, UserService userService) {
        this.emailService = emailService;
        this.userService = userService;
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody EmailRequest emailRequest) {
        String email = emailRequest.getEmail();
        boolean isValidEmail = emailService.validate(email);

        if (isValidEmail) {
            ResetData resetData = userService.generatePasswordReset(email);
            emailService.sendPasswordReset(email, resetData.getResetToken());
            return ResponseEntity.ok(resetData);
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "The email address that you have provided is invalid.");
        }
    }
}

class EmailRequest {
    private String email;

    // Getters and setters
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}

class ResetData {
    private String resetToken;
    private String email;
    private String lastLoggedIn;

    // Getters and setters
    public String getResetToken() {
        return resetToken;
    }

    public void setResetToken(String resetToken) {
        this.resetToken = resetToken;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getLastLoggedIn() {
        return lastLoggedIn;
    }

    public void setLastLoggedIn(String lastLoggedIn) {
        this.lastLoggedIn = lastLoggedIn;
    }
}

@Service
class EmailService {
    public boolean validate(String email) {
        // Implement email validation logic here
        return true;
    }

    public void sendPasswordReset(String email, String resetToken) {
        // Implement email sending logic here
    }
}

@Service
class UserService {
    public ResetData generatePasswordReset(String email) {
        // Implement password reset generation logic here
        return new ResetData();
    }
}

```

We aimed to generate a `resetToken` and deliver it to the specified email. Keep the method concise and focused, without adding extra functionality. Everything should remain **straightforward** and **direct**.


```java
emailService.sendPasswordReset(email, resetData.getResetToken());
```

In this version, emailService is an instance of your email sending service, and resetData.getResetToken() retrieves the resetToken from your reset data object. This keeps the action of sending the password reset straightforward and focused.

## 4. Takeaways:

In short, make sure to follow that:
* **Avoid client-side data filtering** for sensitive information; ensure this is handled at the API level.
* Selectively include only the necessary properties in your response.

{% hint style="info" %}
You can find more details about this topic here:

* [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
{% endhint %}
* [Excessive Data Exposure](https://raw.githubusercontent.com/OWASP/API-Security/master/2019/en/dist/owasp-api-security-top-10.pdf)


