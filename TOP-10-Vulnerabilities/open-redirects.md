# Open Redirects

## 1. Intro:

Insecure redirects and forwards occur when a web application processes user-provided input to determine the target URL for a redirect. If this input is not properly validated, attackers can manipulate it to redirect users to malicious websites. This could enable phishing attacks, where user credentials and other sensitive information are stolen. To understand this vulnerability from an attacker’s perspective, refer to [CWE-601: Open Redirect](https://cwe.mitre.org/data/definitions/601.html).

## 2. Vulnerable Code:

A common example of vulnerable code involves accepting a `url` parameter and using it to redirect the user without proper validation.

```java
...
response.sendRedirect(request.getParameter("url"));
...
```


## 3. Mitigations:

The golden rule you may have noticed throughout these topics is that every developer must **VALIDATE input!** Input validation and filtering are essential to prevent exploitation of any **user-provided input.**  

However, in this particular case, input validation isn’t even necessary. Since developers typically know the destination URL for redirection, there’s no need to use a potentially exploitable `url` parameter. Instead, the redirection target can be hardcoded. 😊  

Check the `Java` tab in the code example below to see an approach that avoids hardcoding the `url` while still securely constructing it.

```java

// build the redirectURL based on the hostname lookup
StringBuilder redirectUrl = new StringBuilder()
    .append(request.getScheme())
    .append("://")
    .append(InetAddress.getLoopbackAddress().getHostName())
    .append(request.getContextPath()
);

//
response.sendRedirect(redirectUrl);
```

## 4. Takeaways:

To use redirects and forwards securely, consider the following best practices:

- Avoid using redirects and forwards altogether, if possible.  
- If they are necessary, **do not use user input** to determine the destination URL.  
- If user input cannot be avoided, ensure that the provided **value** is valid, appropriate for the application, and **authorized** for the user.  
- Sanitize user input by maintaining a list of trusted URLs (using hostnames or regex patterns).  
  - This list should follow an **allow-list approach** rather than relying on a block list.  
- Implement intermediate pages for all redirects to **notify users** that they are leaving your site, clearly display the destination, and require **explicit confirmation via a clickable link.**  

More details:

* [Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
* [Open redirection \(reflected\)](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
* [Insecure URL Redirect](https://application.security/free-application-security-training/owasp-top-10-insecure-url-redirect)

