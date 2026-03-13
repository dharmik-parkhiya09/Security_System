

# Security System Application

A robust and production-ready **Spring Boot** security implementation designed to provide a secure foundation for modern web applications. This project features a dual authentication strategy using **JWT (JSON Web Token)** for stateless REST API security and **OAuth2** for social logins.

## 🚀 Key Features

* **Authentication Mechanisms:**
* **JWT Authentication:** Implements stateless security using short-lived Access Tokens and long-lived Refresh Tokens.
* **OAuth2 Integration:** Seamless social login support for **Google** and **GitHub**.


* **Authorization & RBAC:**
* **Role-Based Access Control (RBAC):** Leverages roles (e.g., ADMIN, USER) and fine-grained permissions to secure endpoints.


* **Account Management:**
* **Secure Registration:** Includes email verification using unique verification tokens.
* **Password Security:** Robust "Forgot Password" and "Reset Password" workflows with expiration-aware tokens.
* **Profile Management:** Endpoints for users to update their profile information and upload profile pictures.


* **Security Utilities:**
* **Refresh Token Rotation:** Secure handling of token renewal to maintain user sessions safely.
* **Exception Handling:** Centralized global exception handler for consistent security and validation error responses.
* **API Documentation:** Integrated **Swagger/OpenAPI** for interactive exploration of all security endpoints.



## 🛠️ Technology Stack

* **Backend:** Java 17+, Spring Boot 3.x.
* **Security:** Spring Security, JWT (io.jsonwebtoken), OAuth2 Client.
* **Persistence:** Spring Data JPA with MySQL/PostgreSQL support.
* **Utilities:** MapStruct for DTO mapping, Lombok for boilerplate reduction, and Java Mail Sender for notifications.
* **Documentation:** Springdoc-openapi (Swagger).

## 📂 Project Structure

```text
src/main/java/com/project/security/
├── config/             # App, Web, and Swagger configurations
├── controller/         # REST Controllers for Auth, Users, and Home
├── dto/                # Data Transfer Objects for requests and responses
├── entity/             # JPA Entities (User, Tokens)
├── enums/              # Role, Permission, and Auth provider types
├── exception/          # Custom exceptions and Global Exception Handler
├── repository/         # Data access layers
├── security/           # JWT filters, Token providers, and OAuth2 handlers
└── service/            # Business logic for Auth, Users, and Emails

```

## ⚙️ Setup and Installation

### 1. Prerequisites

* JDK 17 or higher.
* Maven 3.6+.
* A running MySQL or PostgreSQL database.

### 2. Configure Environment

Update the `src/main/resources/application.properties` file with your credentials:

```properties
# Database Configuration
spring.datasource.url=jdbc:mysql://localhost:3306/your_db
spring.datasource.username=your_username
spring.datasource.password=your_password

# JWT Configuration
app.jwt.secret=your_super_secret_key_at_least_32_chars
app.jwt.expiration-ms=3600000

# Mail Configuration (for verification/reset)
spring.mail.host=smtp.gmail.com
spring.mail.username=your_email@gmail.com
spring.mail.password=your_app_password

```

### 3. Build and Run

```bash
# Clone the repository
git clone https://github.com/dharmik-parkhiya09/security_system.git

# Build the project
mvn clean install

# Run the application
mvn spring-boot:run

```

## 📡 API Endpoints (Highlights)

| Method | Endpoint                | Description | Access |
| --- |-------------------------| --- | --- |
| **POST** | `/auth/register`        | Register a new user | Public |
| **POST** | `/auth/login`           | Login and receive JWT tokens | Public |
| **POST** | `/auth/refresh`  | Refresh an expired access token | Public |
| **GET** | `/users/profile` | Get current user profile | Authenticated |
| **PUT** | `/users/update`  | Update user details/photo | Authenticated |

---

