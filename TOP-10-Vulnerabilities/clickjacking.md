# Clickjacking

## 1. Intro:

   **Clickjacking** is an **interface-based attack** where a user is deceived into **interacting with hidden content** on one website while believing they are engaging with visible elements on another (decoy) website.  

For example, a user might visit a decoy website and click a button to accept a cookie policy. However, unbeknownst to them, this click actually interacts with an invisible button overlaid on the page that, for instance, disables their two-factor authentication on a **vulnerable** website.  

Unlike CSRF attacks, which involve forging requests without the user’s knowledge or input, clickjacking requires the user to **actively perform an action,** such as clicking a button, which is then exploited.  

### Understanding and Mitigating Clickjacking  

#### Learn More:  
For an in-depth look at **Clickjacking** from an attacker's perspective, check out this [resource](https://portswigger.net/web-security/clickjacking).  

---

### 2. Defense Strategies  

Protecting against clickjacking requires **server-side measures**, as there are no reliable client-side defenses. Proper server configuration ensures your website is never used as a "**bait**" for such attacks.  

#### 2.1. Using `X-Frame-Options`  

The `X-Frame-Options` HTTP response header helps control whether a browser can render a page inside a `<frame>` or `<iframe>`. This prevents your content from being embedded on malicious websites, reducing the risk of clickjacking. It is recommended to set this header for all HTML responses.  

Here are the possible values for `X-Frame-Options`:  
- **DENY:** Completely prevents your content from being framed by any domain. This is the safest option and is recommended unless framing is specifically required.  
- **SAMEORIGIN:** Allows the content to be framed only by the current site.  
- **ALLOW-FROM URI:** Permits framing by a specific domain or URI.  

---

#### 2.2. Implementing Content Security Policy (CSP)  

A **Content Security Policy (CSP)** provides a robust way to mitigate clickjacking and other attacks like XSS. It is applied through the HTTP response header in the following format:  
```
Content-Security-Policy: policy
```  
Here, `policy` contains directives defining allowed sources and behaviors for your application.  

For clickjacking prevention, use the **`frame-ancestors`** directive, which specifies valid sources allowed to embed your content:  
- **`frame-ancestors 'none';`** Blocks all framing, similar to `X-Frame-Options: DENY`.  
- **`frame-ancestors 'self';`** Allows framing only within the same domain, similar to `X-Frame-Options: SAMEORIGIN`.  
- To permit specific domains, use:  
  ```
  Content-Security-Policy: frame-ancestors example.com;
  ```  

---

### 3. Key Takeaways  

Both `X-Frame-Options` and `Content-Security-Policy` headers are essential for preventing clickjacking by controlling if and how your web pages can be embedded in `<iframe>` elements.  

As this is more about server-side configuration than vulnerable code, explore this [interactive resource](https://application.security/free-application-security-training/owasp-top-10-clickjacking) for a deeper understanding of clickjacking behavior and mitigation techniques.  

{% hint style="info" %}
More details about this topic here:
* [What is clickjacking?](https://portswigger.net/web-security/clickjacking)
{% endhint %}\
* [Clickjacking Defense \[OWASP\]](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html#defending-with-content-security-policy-csp-frame-ancestors-directive)
* [Clickjacking  \| Kontra exercise](https://application.security/free-application-security-training/owasp-top-10-clickjacking)


