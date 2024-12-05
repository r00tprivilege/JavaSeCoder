# SQLi \[SQL Injections\]

## 1. Intro: 

SQL Injection vulnerabilities occur when developers construct **dynamic database queries** incorporating **user-provided input**. To prevent this, developers should:

1. Avoid using **dynamic queries** in their applications altogether.  
2. **Sanitize and properly escape all user input** before incorporating it into queries.  

These principles are broadly applicable across various programming languages and database systems.

## 2. Vulnerable Code:


```java
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @PostMapping("/login")
    public ResponseEntity<String> authenticate(@RequestParam String email, @RequestParam String password) {
        String sqlQuery = "SELECT COUNT(*) FROM users WHERE email = ? AND password = ?";
        
        try {
            Integer userCount = jdbcTemplate.queryForObject(sqlQuery, new Object[]{email, password}, Integer.class);
            if (userCount != null && userCount == 1) {
                // Authentication successful
                return ResponseEntity.ok("Login successful");
            } else {
                // Authentication failed
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
            }
        } catch (Exception e) {
            // Handle exception (e.g., log the error)
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred");
        }
    }
}
```


The **`sqlQuery`** executes an **SQL query** without performing any input validation. This means it does not verify whether the input contains valid characters, adheres to length constraints, or removes potentially harmful characters.

This lack of validation allows an attacker to inject **raw SQL commands** directly into the username and password fields. By doing so, they can manipulate the behavior of the underlying **SQL query** used for authentication, potentially bypassing the application's security. For example, an attacker might use an input like:  
`' OR 1=1 --`  
to gain unauthorized access by altering the query's logic.

## **3. Mitigation:**

[SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) attacks remain **alarmingly common**, primarily due to two reasons:  

1. The **widespread presence of SQL Injection vulnerabilities** in applications.  
2. The **high value of the target**, as databases often store the most sensitive and critical data for an application.  

It’s concerning that **SQL Injection attacks** still succeed frequently, especially since they are relatively easy to prevent. This guide will outline the **top 4 most effective methods** to build a **secure** and **resilient application** to safeguard against such vulnerabilities.

### **3.1. Prepared statements:**

Using **prepared statements with variable binding** (also known as **parameterized queries**) is the best practice for writing SQL queries. They are **easy to implement** and **more readable** than dynamic queries. With parameterized queries, developers define the SQL structure first and pass the input parameters separately. This approach ensures the database can **distinguish between query logic and user input**, regardless of what the input contains.

Prepared statements **prevent attackers from altering the intended query logic**, even if malicious SQL commands are included in the input. For example, if an attacker inputs `sample@mail.com' or '1'='1`, the **parameterized query** treats it as a plain string value. The query will only search for a username that matches the exact string `sample@mail.com' or '1'='1`, rendering the injection attempt ineffective.


```java
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @PostMapping("/login")
    public ResponseEntity<String> authenticate(@RequestParam String email, @RequestParam String password) {
        String sqlQuery = "SELECT COUNT(*) FROM users WHERE email = ? AND password = ?";

        try {
            // Execute the query with parameterized input
            Integer count = jdbcTemplate.queryForObject(sqlQuery, new Object[]{email, password}, Integer.class);

            if (count != null && count == 1) {
                // Authentication successful
                return ResponseEntity.ok("Login successful");
            } else {
                // Authentication failed
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
            }
        } catch (Exception e) {
            // Handle exceptions (e.g., log the error)
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred");
        }
    }
}
```
Explanation of the Code:
Dependency Injection:

JdbcTemplate is injected via @Autowired to handle database operations securely and efficiently.
Parameterized Query:

The ? placeholders in the SQL query ensure that user input is properly escaped, preventing SQL injection.
Error Handling:

Catches exceptions during the database query and returns a generic error message while logging the details.
Authentication Logic:

The query checks if a user exists with the provided email and password. If the count is 1, authentication is successful; otherwise, it fails.
Recommendations for Improvement:
Password Security: Never store passwords as plain text in the database. Use a strong hashing algorithm like BCrypt or Argon2 for password storage and comparison.
Spring Security: For real-world applications, integrate Spring Security for more robust authentication mechanisms and centralized security management.
This approach ensures both security and scalability while adhering to Spring Boot best practices.



Wherever **executing SQL queries** is necessary, make sure **to always use** [prepared statements and query parametrization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html).

### 3.2. Stored procedures:

**Stored procedures** are not inherently immune to SQL Injection (SQLi). However, when **properly implemented**, certain **standard stored procedure programming practices** can function similarly to **parameterized queries**, providing the same level of security.

When using stored procedures, developers are required to **build SQL statements with parameters** that are automatically handled by the database, unless they deviate from standard practices. The main difference between prepared statements and stored procedures is that with stored procedures, the **SQL code is pre-defined and stored** in the **database**, and it is **called from the application** when needed.

Both methods—**prepared statements** and **stored procedures**—are equally effective in preventing SQL Injection, so the choice between them depends on which approach best fits your organization's needs.

Below is a basic example of how a stored procedure can be implemented in SQL.

```sql
CREATE PROCEDURE SafeAuth(@username varchar(50),  @password varchar(50))
AS
BEGIN
DECLARE @sql varchar(150)
    SELECT Username,Password FROM dbo.Login
    WHERE Userame=@username AND Password=@password
end
```

**Note**: **"Implemented safely"** means that the **stored procedure** does not include any **unsafe dynamic SQL generation**. While developers typically avoid generating dynamic SQL inside stored procedures, it is possible, but **should be avoided**. If dynamic SQL cannot be avoided, it is essential for the stored procedure to use **input validation** or **proper escaping**, as outlined in this article, to ensure that **user-supplied input** cannot be used to inject SQL code into the dynamically generated query.

While stored procedures can be an effective defense against SQL Injection, it is important to also use them in conjunction with other techniques, such as **prepared statements**, for added security.
### 3.3. Input validation:

There is two types of input validation: **syntactical** and **semantical.**

**Syntactical validation** ensures the correctness of the syntax for **structured fields** (e.g., SSN, date, currency symbol, etc.).

**Semantic validation**, on the other hand, checks that the **values** entered are correct within the specific **business context** (e.g., ensuring a start date is before the end date, or a price falls within a defined range).

**Input validation** can be achieved using various programming techniques that enforce both syntactic and semantic correctness. Some common methods include:

However, it is **crucial** to recognize that any **client-side JavaScript validation** can be bypassed by an attacker who disables JavaScript or uses a Web Proxy. Therefore, it is essential to ensure that **server-side validation** is also implemented to maintain security.

* **Data type validators** in Java and Spring Boot can be easily implemented using annotations such as `@NotNull`, `@Size`, `@Email`, and `@Min` from the `javax.validation` package or `Spring Validation` framework. These annotations help enforce basic validation rules for fields in your model classes.
  
* You can validate input against **[JSON Schema](https://json-schema.org/)** and **[XML Schema (XSD)](https://www.w3schools.com/xml/schema_intro.asp)** using libraries like `Jackson` for JSON validation or `JAXB` for XML validation. These libraries allow you to ensure that the input adheres to the expected schema format.

* **Type conversion** in Java (e.g., `Integer.parseInt()` to convert strings to integers, `LocalDate.parse()` to convert strings to dates) should always be accompanied by strict exception handling using `try-catch` blocks. This ensures that invalid input is properly handled and prevents errors from propagating.

* Implement **minimum and maximum value checks** for numerical parameters and dates using annotations like `@Min` and `@Max` in Spring Boot. Similarly, for strings, you can check the **minimum and maximum length** using the `@Size` annotation.

* For string parameters with limited sets of allowed values (e.g., days of the week), you can use a custom validator or define the allowed values using Java's `Enum` type or simple `if` statements.

* **Regular expressions** can be used in Java to validate more complex structured data. The `Pattern` class can compile regular expressions, and it’s essential to cover the entire input string (`^...$`) without using the "any character" wildcard (`.` or `\S`). Be sure to refer to comprehensive resources like [Regular Expressions Info](https://www.regular-expressions.info/) when building these patterns, as they can be complex to develop.

Since input validation is critical to security and proper user interaction in web applications, it’s important to ensure proper implementation. You can [**learn more about input validation best practices**](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).


### 3.4. User-supplied input Escaping:

This technique should **only be used as a last resort** when none of the previous methods are **feasible**. Input validation is generally a better approach, as this technique is more fragile and **cannot guarantee** to prevent all **SQL Injection (SQLi)** attacks in every situation.

Consider the following scenario: each **Database Management System (DBMS)** typically supports one or more character escaping schemes specific to different types of queries. If you **escape all user-supplied input** using the **appropriate escaping scheme** for the database in use, the **DBMS will treat the input as data**, not SQL code, thus preventing potential **SQL injection vulnerabilities**.

Escaping user input should generally be considered an additional layer of defense on top of more robust methods, such as **prepared statements** or **stored procedures**. In Java and Spring Boot, this can be achieved by using **language-specific methods** or database-specific libraries or adapters that automatically handle query escaping. For instance, libraries like `JDBC` or `JPA` in Spring Boot, when properly configured, can ensure that user inputs are escaped to avoid SQLi risks.

In Java, it's always better to rely on **parameterized queries** or **ORM frameworks** like **Hibernate** that automatically handle input sanitization and escaping, rather than manually handling escaping.


In Java Spring Boot, you can safely create and execute parameterized SQL queries using JdbcTemplate. Here's how you can format and execute a query with user input, similar to the JavaScript example:

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    public void fetchUserById() {
        int userId = 1;
        String sql = "SELECT * FROM users WHERE id = ?";
        
        // Using JdbcTemplate to safely execute the query with parameterized input
        jdbcTemplate.queryForList(sql, userId)
                    .forEach(row -> System.out.println(row));
    }
}
```
Key Points:
JdbcTemplate: In Spring Boot, JdbcTemplate is used to execute SQL queries. It simplifies the process of querying the database and automatically handles parameterized queries, preventing SQL injection.
Parameterized Query: The ? in the SQL query acts as a placeholder for the user input (userId), which is safely passed as a parameter when executing the query.
Security: This approach avoids the risks associated with directly concatenating user input into SQL queries, ensuring that user input is properly sanitized.

## 4. Takeaways:

**SQL Injection Shouldn't Be a Problem!** That's the goal we should all strive for, and it’s entirely achievable! If every Java Spring Boot developer follows these best practices:

1. **Use Prepared Statements** for all SQL queries to ensure safe and efficient execution.
2. **Validate and sanitize all user inputs** to protect against malicious data being executed.
3. **Write clean, efficient code** with proper exception handling and logging.

By adopting these principles, **SQL Injection vulnerabilities** will become a thing of the past! Let’s make secure coding the standard.

Find more details about this topic here:

* [OWASP Cheatsheet against SQLI](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [Preventing python SQLI](https://realpython.com/prevent-python-sql-injection/)
* [Query parametrization Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [Injection prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

