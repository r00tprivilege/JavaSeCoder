# Cross-Site Scripting \[XSS]

## 1. Intro:

However, we will not delve into the potential consequences of XSS exploits. For more details on the impact of such attacks, you can refer to this resource: [OWASP XSS Attack Overview](https://owasp.org/www-community/attacks/xss/).

Even if your server is secure, hackers often target web browsers, as they execute any JavaScript present on a web page. Given the prevalence of cross-site scripting attacks, they can generally be categorized into three main types:

* **Stored XSS.**
* **Reflected XSS.**
* **DOM-Based XSS.**

## 2.1. Stored XSS:

**Stored XSS attacks**, also known as **Persistent** or **Type-I XSS**, occur when a malicious script is permanently saved on the target server, such as in a database, comment section, message forum, or visitor log. When a victim requests the stored data, the server delivers the malicious script as part of the response, executing it in the victim's browser.

### 2.1.1. Escaping HTML Characters:

The first step in preventing **stored cross-site scripting** is to ensure that all dynamic content retrieved from a database is properly escaped. This allows the browser to treat the content within HTML tags as plain text rather than interpreting it as raw HTML.

| **Character** | **Entity encoding** |
| ------------- | ------------------- |
| &             | **\&amp;**          |
| **'**         | **\&apos;**         |
| **<**         | **\&lt;**           |
| **>**         | **\&gt;**           |

Here’s an example of how escaping and displaying data retrieved from a database might be implemented:

```markup
<div class="message">
    <h1> Hi there:
        &lt;script&gt;alert(&quot;Hey&quot;)&lt;/script&gt;
    </h1>
</div>
```

This transformation of escaped characters takes place **after** the browser has constructed the page's DOM, ensuring that the `<script>` tag is treated as plain text rather than being executed. Given how **prevalent** cross-site scripting vulnerabilities are, most modern **front-end frameworks** automatically **escape dynamic content** by default. Typically, **string** variables in views are escaped automatically to enhance security.

In Java Spring Boot, escaping responses is handled differently compared to front-end frameworks like React. Spring Boot relies on server-side rendering (SSR) and uses libraries such as Thymeleaf for rendering templates securely. These libraries escape dynamic content automatically to prevent cross-site scripting (XSS) attacks.
Code Example in Spring Boot (with Thymeleaf):
Here’s how the equivalent scenario would be handled in a Spring Boot application using Thymeleaf:

```java
@Controller
public class UserProfileController {
    @GetMapping("/profile")
    public String getUserProfile(Model model) {
        String message = "<script>alert('Hey')</script>";
        model.addAttribute("message", message);
        return "profile"; // Refers to a Thymeleaf template named "profile.html"
    }
}

```
Thymeleaf template (profile.html):

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>User Profile</title>
</head>
<body>
    <div class="message">
        <h1>Hello, this is the message: <span th:text="${message}"></span>!</h1>
    </div>
</body>
</html>
```

Explanation of Escaping in Spring Boot:
Dynamic Content Handling:

In Thymeleaf, when you use th:text to render dynamic content, it escapes special characters like <, >, and " by default. This ensures that content such as <script>alert('Hey')</script> is rendered as text rather than executable code in the browser.
Automatic Escaping: 

The escaping process converts special characters into their HTML entities. 

For example:
< becomes &lt;
> becomes &gt;

This prevents the browser from interpreting the content as raw HTML or JavaScript.

Safe by Default:

Unlike in React, where the developer must ensure escaping (either via libraries or functions), Spring Boot with Thymeleaf applies escaping by default for all content rendered using th:text. This reduces the likelihood of XSS vulnerabilities.
Customization:

If the developer explicitly wants to render raw HTML (not recommended without validation), they can use th:utext. However, this bypasses the escaping mechanism and must be used cautiously.


Although **front-end frameworks generally escape dynamic content by default,** this only applies to **displaying the content**. When using dynamic data in attributes like `<a href={...}>` or `<img src={...}>`, developers must **implement additional defensive measures** to ensure the data is properly escaped and sanitized.

### 2.1.2. Implementing CSP Headers \[Content Security Policy]:

We’ll cover everything about Content Security Policies (CSP) on a dedicated page, but it’s worth highlighting some key aspects of how CSPs help defend against cross-site scripting.

Modern browsers enable websites to define a content security policy, which can be used to **restrict JavaScript execution** on your site.  

For instance, a simple policy might restrict scripts to being loaded only from the **same domain** (`self`) and explicitly prevent the browser from executing **inline JavaScript**.

```markup
Content-Security-Policy: script-src 'self' https://scripts.samplesite.com
```

You can define your site’s content security policy by adding it to the `<head>` section of your web pages in the HTML.

## 2.2. Reflected XSS:

**Reflected XSS attacks** occur when a malicious script is reflected off the web server and included in the server's response, such as in error messages, search results, or any part of a response that incorporates user input from the request.  

In these attacks, the victim is tricked into **clicking a malicious link**, submitting a specially crafted form, or visiting a malicious website. The injected code is sent to the vulnerable server, which **reflects** it back in the response. Since the response originates from a "trusted" server, the victim's browser executes the malicious script. **Reflected XSS** is also referred to as **Non-Persistent** or **Type-II XSS**.


### 2.2.1. Escapic Dynamic Contents from Requests:

This mitigation is similar to the one discussed in **2.1.1.** Whether the dynamic content originates from the backend/database or the HTTP request, it is **escaped in the same manner**. Fortunately, modern front-end templates automatically escape all variables, regardless of their source (whether from the HTTP request or the backend).

Reflected XSS often targets areas such as search pages and error pages, as they display parts of the **query string back to the user**.

## 2.3. Document Object Model \[DOM]-Based XSS:

**DOM-based XSS vulnerabilities** typically occur when **JavaScript** retrieves data from an attacker-controlled source, such as the URL, and passes it to a sink that can execute dynamic code, like `eval()` or `innerHTML`. This allows attackers to run malicious JavaScript, often enabling them to take control of other users' accounts.

While **Reflected** and **Stored XSS** are _server-side_ injection issues, **DOM-based XSS** is a _client-side_ (browser) issue. In **Reflected/Stored** XSS, the attack is injected into the application during the **server-side** processing of requests, where untrusted input is **dynamically** incorporated into HTML. For **DOM XSS**, the attack occurs during runtime on the **client side** directly within the browser.

Check out [**this great resource on DOM XSS**](https://domgo.at/cxss/intro) for an in-depth look at analyzing source code and identifying vulnerabilities.

### 2.3.1. Vulnerable Code Sample:

The core logic of filtering items based on a query parameter (filter) will be handled in a Spring Boot controller. The server will return the filtered list of items, and the client-side code will display those items dynamically (usually through Thymeleaf templates or AJAX).

Here’s how to structure the Java Spring Boot implementation:

1. Backend (Spring Boot Controller)
In the Spring Boot controller, we will handle the query parameter and return the filtered list of items to the front-end.

```java
@Controller
public class ItemController {

    @Autowired
    private ItemService itemService;  // Service that fetches items from a repository or database

    @GetMapping("/items")
    public String getItems(@RequestParam(name = "filter", required = false) String filter, Model model) {
        List<Item> items;

        if (filter != null && !filter.isEmpty()) {
            items = itemService.filterItemsByType(filter.replace('+', ' '));  // Replace '+' with space
        } else {
            items = itemService.getAllItems();
        }

        model.addAttribute("items", items);
        model.addAttribute("currentType", filter);  // Add the current filter to the model
        return "items";  // Thymeleaf template to render the items
    }
}
```

2. Service Layer
In the service layer, we will filter the items based on the filter query parameter.

```java
@Service
public class ItemService {

    // Assuming you have a repository to fetch data from a database or any data source
    @Autowired
    private ItemRepository itemRepository;

    public List<Item> getAllItems() {
        return itemRepository.findAll();  // Fetch all items from the database
    }

    public List<Item> filterItemsByType(String type) {
        return itemRepository.findByType(type);  // Filter items by the given type
    }
}

```

3. Model (Item Entity)
You need a simple model representing the Item.

```java
@Entity
public class Item {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String description;
    private String owner;
    private String type;  // Represents the item type
    private String icon;

    // Getters and setters...
}

```
4. Repository (ItemRepository)
Assuming you're using Spring Data JPA, you'll create a repository interface for accessing your database.

```java
public interface ItemRepository extends JpaRepository<Item, Long> {
    List<Item> findByType(String type);  // Custom query to find items by their type
}

```

5. Front-End (Thymeleaf Template)
In the Thymeleaf template, we will display the items dynamically. This replaces the JavaScript functionality of updating the DOM.

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Items</title>
</head>
<body>
    <div>
        <h1>Items - Type: <span th:text="${currentType}">Current Type</span></h1>
    </div>

    <div id="list">
        <div th:each="item : ${items}">
            <div>
                <img th:src="${item.icon}" alt="Item Icon">
                <p th:text="${item.name}"></p>
                <p th:text="${item.description}"></p>
                <p th:text="${item.owner}"></p>
            </div>
        </div>
    </div>

    <div>
        <a th:each="item : ${items}" th:href="@{'/items?filter=' + ${item.type}}" th:text="${item.type}"></a>
    </div>

    <script>
        // Add JavaScript to handle updating URL and re-rendering content if needed
        document.addEventListener('DOMContentLoaded', () => {
            const itemLinks = document.querySelectorAll('.itemlink');
            
            itemLinks.forEach(link => {
                link.addEventListener('click', (event) => {
                    const filterValue = event.target.innerText;
                    window.location.href = `/items?filter=${filterValue}`;
                });
            });
        });
    </script>
</body>
</html>


```
6. How it Works
The Spring Boot controller handles the logic for retrieving items, either filtered by the filter query parameter or all items if no filter is provided.
The filtered items are passed to the Thymeleaf template, which renders the list of items and their details.
The filter value is updated in the URL when a user clicks on a type, and the page reloads with the updated filter applied.

7. Client-Side JavaScript
While the main logic is server-side in Spring Boot, the page can still contain JavaScript for other purposes like updating the URL without reloading the page or handling other client-side interactions. However, in this case, the filtering and rendering are handled by Spring Boot with Thymeleaf, and JavaScript is only used for dynamic behaviors.


### 2.3.2. Mitigation:

In a Java Spring Boot environment, escaping user input to prevent Stored XSS and Reflected XSS is done on the server side, primarily within controllers and service layers. The equivalent function in Java would escape the HTML content to ensure it's safe before rendering it in a template, using Java's built-in string escaping methods or libraries like Apache Commons Text.

Here’s how you can implement an equivalent of your JavaScript escapeHTML function in Java for use in a Spring Boot application.

1. Java Method for Escaping HTML
To prevent XSS attacks, you would create a method in a service or utility class to escape user input. Here’s how you could write an escapeHTML method in Java:

```java
import org.apache.commons.text.StringEscapeUtils;

public class HtmlEscapeUtil {

    public static String escapeHTML(String input) {
        if (input == null) {
            return null;
        }
        // Using Apache Commons Text's StringEscapeUtils to escape HTML
        return StringEscapeUtils.escapeHtml4(input);
    }
}
```
In this example:

We use Apache Commons Text's StringEscapeUtils.escapeHtml4() to escape the HTML content. This method escapes common HTML special characters like &, <, >, ", and ' to their respective HTML entities, similar to what your JavaScript function does.
The escapeHTML method checks if the input is null and escapes the string appropriately to avoid XSS vulnerabilities when the string is rendered.
You need to add Apache Commons Text as a dependency in your pom.xml to use StringEscapeUtils:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.9</version> <!-- Use the latest version -->
</dependency>
```
2. Using the escapeHTML Method in Spring Boot
In your Spring Boot controller or service, you can call the escapeHTML method before adding user-generated content to the model, ensuring the input is safely escaped before it reaches the front-end.

Here’s an example of how you could apply this in a Spring Boot controller:

```java
@Controller
public class UserProfileController {

    @Autowired
    private ItemService itemService;

    @GetMapping("/profile")
    public String getUserProfile(@RequestParam(name = "username") String username, Model model) {
        // Escape the username to prevent XSS
        String safeUsername = HtmlEscapeUtil.escapeHTML(username);

        // Get user data (e.g., items or profile information)
        UserProfile profile = itemService.getUserProfile(safeUsername);
        
        // Add the escaped username and profile data to the model
        model.addAttribute("username", safeUsername);
        model.addAttribute("profile", profile);

        return "profile"; // Thymeleaf template
    }
}

```

In this controller:

- The username parameter from the request is passed through the escapeHTML function before it’s added to the model. This ensures that the username is safely rendered in the view and is not vulnerable to XSS.
- The profile data or any other dynamic content fetched from the backend would also be escaped similarly before rendering.

3. Rendering in Thymeleaf
In the Thymeleaf template, you don’t need to worry about manually escaping user-generated content, because Thymeleaf automatically escapes variables in th:text. For example:

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>User Profile</title>
</head>
<body>
    <div>
        <h1>Welcome, <span th:text="${username}"></span>!</h1>
    </div>
    <!-- Other content goes here -->
</body>
</html>

```
In this template:

- The username variable is automatically escaped by Thymeleaf, ensuring that any potentially harmful characters (e.g., <script>) are displayed as text rather than being executed by the browser.

4. Sanitizing User Input (Optional)
If you want to further sanitize user input and strip any potentially malicious tags (beyond escaping), you can use libraries like JSoup to clean the input before it’s stored or displayed.

```java
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

public class HtmlSanitizeUtil {

    public static String sanitizeHTML(String input) {
        if (input == null) {
            return null;
        }
        // Use JSoup to clean the input and remove any unwanted tags/attributes
        return Jsoup.clean(input, Safelist.basic());
    }
}
```
You can use sanitizeHTML along with escapeHTML for added security when handling user-generated content.

## 3. Takeaways:
- Escape HTML: On the server side, escaping HTML before rendering it in templates is crucial for preventing XSS attacks.
- Thymeleaf: Thymeleaf automatically escapes variables rendered with th:text, so it’s easier to protect against reflected XSS vulnerabilities.
- Libraries: Use libraries like Apache Commons Text (StringEscapeUtils) for HTML escaping or JSoup for sanitizing input.

This approach ensures that both stored and reflected XSS vulnerabilities are mitigated, similar to the JavaScript example you provided, but on the server side using Java Spring Boot.

You can find more details about this topic here:

* [Stored XSS Example](https://application.security/free-application-security-training/owasp-top-10-stored-cross-site-scripting)
* [Reflected XSS Example](https://application.security/free-application-security-training/owasp-top-10-reflected-cross-site-scripting)
* [DOM XSS Example](https://application.security/free-application-security-training/owasp-top-10-dom-cross-site-scripting)
* [XSS Prevention Cheatsheet\[OWASP\]](https://cheatsheetseries.owasp.org/cheatsheets/Cross\_Site\_Scripting\_Prevention\_Cheat\_Sheet.html)
* [DOM XSS Prevention Cheatsheet\[OWASP\]](https://cheatsheetseries.owasp.org/cheatsheets/DOM\_based\_XSS\_Prevention\_Cheat\_Sheet.html)
* [What is DOM-based XSS?](https://portswigger.net/web-security/cross-site-scripting/dom-based)
