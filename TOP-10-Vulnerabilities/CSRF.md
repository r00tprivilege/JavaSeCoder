# CSRF \[Cross-Site Request Forgery\]

## 1. Intro:

Cross-site request forgery (**CSRF**) is a web security flaw that allows attackers to trick users into performing actions they didn't intend to. This vulnerability exploits the same-origin policy, which is meant to prevent websites from affecting each other, by causing a user to make an unintended request. In typical CSRF attacks, a malicious **`GET`** request is used to alter the state of a web server.

To learn more about this vulnerability from the attacker's perspective, you can read further [here](https://portswigger.net/web-security/csrf).

## 2. Method to Defense:

### 2.1. Following the REST architecture:

**REST** or **Representational State Transfer** states that **`GET`** requests should The **`GET`** method should be strictly reserved for retrieving data or other resources. For any actions that modify the server state, you **should** use the appropriate methods like **`PUT`**, **`POST`**, or **`DELETE`**.

Since not every action has a direct HTTP method mapping (e.g., fetching = **`GET`**, updating = **`POST`**, creating = **`PUT`**, deleting = **`DELETE`**), additional security measures are necessary to protect the application. However, it’s crucial to remember that **`GET`** should **only** be used for fetching data.

### 2.2. Using CSRF tokens:

This is considered one of the most effective methods for properly mitigating CSRF.

{% hint style="info" %}
**CSRF tokens protect against CSRF attacks** because, without them, **an attacker is unable to generate valid requests** to the **backend server**.
{% endhint %}

Here are several techniques and use cases for utilizing these tokens.

#### 2.2.1. Synchronizer token:

Ideally, **CSRF tokens should be stored on the server-side**, where they can be implemented as either **per-session** or **per-request** tokens, depending on the application's needs.

**Per-request** tokens offer enhanced security compared to **per-session** tokens because their validity is limited to a shorter timeframe. However, this added security can come at the cost of usability, as features like the browser's "back" button might not function properly due to expired tokens.

When the client sends a request, the server should validate the token included in the request against the one stored in the session. If the token is missing or does not match, the server should reject the request and potentially flag it as a suspected CSRF attack.

When designing CSRF tokens, developers should ensure that they meet the following criteria:

- **Unique** for each user session.
- Kept **secret**.
- **Unpredictable**, typically generated using a secure method.

{% hint style="danger" %}
**CSRF tokens** must **NOT** be sent via cookies.
{% endhint %}

**CSRF tokens** can be included using hidden fields, headers, and applied to forms or AJAX requests. It's crucial to ensure there are no unintended exposures, such as through server logs or URLs. Below is an example of implementing a token in a form.

```markup
<form action="/sell" method="post">
    <input type="hidden" name="CSRFtoken" value="aWYgeW91IGZpbmQgaXQsIHlvdSBhcmUgbXkgQkZGLg==">
    [...]
</form>
```

#### 2.2.2. Double submit cookies:

Managing state for CSRF tokens can sometimes be challenging, making the double submit cookie technique a viable alternative to the synchronizer token pattern.

In this approach, when a user visits the website (ideally before authentication), the server securely generates a token and sets it as a cookie in the user's browser. For every subsequent request, the application requires the token to be included as a hidden value in the form. On the server side, the request is validated by comparing the value from the hidden form field with the value stored in the cookie. If the two match, the request is deemed legitimate; otherwise, it is rejected.

{% hint style="info" %}
It’s important to note that this technique is more of a workaround and is best combined with additional security measures, such as encrypting the cookies or utilizing [**HMAC**](https://www.nedmcclain.com/better-csrf-protection/) for enhanced protection.
{% endhint %}

### 2.3. Using Custom Request Headers:

Implementing CSRF tokens using the double submit cookie method or other UI-altering defenses can often be complex or problematic.
Since methods like **`POST`**, **`PUT`**, **`PATCH`**, and **`DELETE`** involve state changes, they should include a CSRF token as part of the request. 
Here is how you can implement CSRF prevention using a custom request header in a Java Spring Boot application:

1- Configure Spring Security to Use a Custom CSRF Token Header

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Configuration
public class SecurityConfig extends org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf
                .csrfTokenRepository(csrfTokenRepository())
        ).addFilterAfter(csrfTokenResponseHeaderBindingFilter(), CsrfFilter.class);
    }

    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-Security-Token"); // Custom header name for CSRF token
        return repository;
    }

    private OncePerRequestFilter csrfTokenResponseHeaderBindingFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws java.io.IOException, javax.servlet.ServletException {
                CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
                if (csrfToken != null) {
                    response.setHeader(csrfToken.getHeaderName(), csrfToken.getToken());
                }
                filterChain.doFilter(request, response);
            }
        };
    }
}

```
2- Frontend JavaScript Code to Include the Custom CSRF Header

```html
<script type="text/javascript">
    const csrfTokenValue = document.querySelector("meta[name='csrf-token']").getAttribute("content");

    axios.defaults.headers.post['X-Security-Token'] = csrfTokenValue;
    axios.defaults.headers.put['X-Security-Token'] = csrfTokenValue;
    axios.defaults.headers.delete['X-Security-Token'] = csrfTokenValue;
    axios.defaults.headers.patch['X-Security-Token'] = csrfTokenValue;
</script>

```

3- Backend Controller Example
```java
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class MyController {

    @PostMapping("/example")
    public String handlePost(@RequestBody String payload) {
        return "Request processed with CSRF protection.";
    }
}

```
### Key Points:
#### The CSRF token is generated by Spring Security and attached to the response headers.
#### The frontend includes this token in every state-changing request via a custom header.
#### Spring Security validates the token on each request using the configured X-Security-Token header.

### 2.4. Using CSRF middleware for prevention:

Ultimately, leveraging a well-established solution, such as a trusted security library, is one of the most secure approaches to implement defenses. For Java Spring Boot developers, I'll demonstrate how Spring Security's built-in CSRF protection can be used to effectively generate and manage CSRF tokens.

To implement CSRF prevention in a Java Spring Boot application, you can utilize Spring Security's CSRF protection, which works similarly to the Node.js example you provided. Below is a Java Spring Boot version of the code that achieves the same goal by leveraging the CSRF middleware:

### 1. **Spring Security Configuration**

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf()
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())  // CSRF Token stored in a cookie
            .and()
            .authorizeRequests()
            .antMatchers("/form", "/process").permitAll()  // Allow access to these endpoints without authentication
            .anyRequest().authenticated();  // Other endpoints require authentication
    }
}
```

### 2. **Controller to Handle Form and Process Requests**

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class FormController {

    // Endpoint to render the form with the CSRF token
    @GetMapping("/form")
    public String showForm(HttpServletRequest request, Model model) {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");
        model.addAttribute("csrfToken", csrfToken.getToken());  // Add CSRF token to the model
        return "form";  // Return the view name (form.html or form.jsp depending on your template engine)
    }

    // Endpoint to process the form data
    @PostMapping("/process")
    public String processForm(@RequestParam("data") String data) {
        // Process the form data
        return "data is being processed: " + data;
    }
}
```

### 3. **HTML Form with CSRF Token**

In the view (`form.html`), you'll include the CSRF token as a hidden input field to ensure it is sent with the form data.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="csrf-token" content="${csrfToken}">
    <title>Form</title>
</head>
<body>
    <form action="/process" method="POST">
        <input type="hidden" name="_csrf" value="${csrfToken}">  <!-- CSRF Token -->
        <label for="data">Enter some data:</label>
        <input type="text" id="data" name="data">
        <button type="submit">Submit</button>
    </form>
</body>
</html>
```

### Explanation:
1. **SecurityConfig**: Configures CSRF protection with the CSRF token stored in cookies (`CookieCsrfTokenRepository.withHttpOnlyFalse()` ensures the CSRF token is accessible to JavaScript in the browser).
2. **FormController**: Handles the `/form` endpoint to serve the form with a CSRF token and the `/process` endpoint to process the submitted form.
3. **form.html**: This view contains the form that includes the CSRF token as a hidden input field, which will be automatically checked by Spring Security when the form is submitted.

This setup ensures that CSRF protection is enabled and that CSRF tokens are securely handled with each request.


## 3. Takeaways:

Defending against CSRF is a multi-faceted challenge that requires developers to adhere to the **REST architecture** while ensuring the implementation of mandatory CSRF tokens. While following established security practices is crucial in application security, developers can also leverage **CSRF protection middleware** as an additional layer of defense.

{% hint style="info" %}
Find more details about this topic here:

* [Should I use CSRF protection on Rest API endpoints?](https://security.stackexchange.com/questions/166724/should-i-use-csrf-protection-on-rest-api-endpoints/166798#166798)
* [CSRF Protection Cheatsheet \[OWASP\]](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#javascript-guidance-for-auto-inclusion-of-csrf-tokens-as-an-ajax-request-header)
* [Preventing CSRF](https://auth0.com/blog/cross-site-request-forgery-csrf/)
{% endhint %}

