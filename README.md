

# Security System Application

A robust Spring Boot security implementation featuring **JWT (JSON Web Token)** authentication, **OAuth2** integration (Google), and **Role-Based Access Control (RBAC)**.

## 🚀 Features

* **Authentication**: Supports both local login and Social Login via Google OAuth2.
* **JWT Management**: Implements Access Tokens and Refresh Tokens for secure, stateless session management.
* **Authorization**: Detailed RBAC using Roles (`ADMIN`, `USER`, `MANAGER`, `MODERATOR`) and specific Permissions.
* **Email Services**: Integration for sending HTML-based emails using Thymeleaf templates.
* **Documentation**: Integrated Swagger/OpenAPI for easy API testing.

## 🛠️ Tech Stack

* **Framework**: Spring Boot 3.x.
* **Security**: Spring Security 6.
* **Database**: MySQL.
* **Persistence**: Spring Data JPA with Hibernate.
* **Documentation**: Springdoc-openapi.
* **Utility**: Lombok, MapStruct (implied for DTO mapping).

## 📋 API Endpoints

### Authentication Controller (`/auth`)

| Method | Endpoint | Description | Access |
| --- | --- | --- | --- |
| POST | `/register` | Register a new user | Public |
| POST | `/login` | Authenticate and receive JWTs | Public |
| POST | `/refresh-token` | Renew an expired Access Token | Public |
| POST | `/logout` | Invalidate current session | Authenticated |

### User Management (`/users`)

| Method | Endpoint | Description | Access |
| --- | --- | --- | --- |
| GET | `/me` | Get current logged-in user profile | Authenticated |
| GET | `/{id}` | Get specific user details | Admin/Manager |
| PUT | `/{id}` | Update user information | Owner/Admin |

## ⚙️ Configuration

The application requires the following environment variables or properties in `application.properties`:

```properties
# Database Configuration
spring.datasource.url=jdbc:mysql://localhost:3306/security
spring.datasource.username=${DB_USERNAME}
spring.datasource.password=${DB_PASSWORD}

# JWT Configuration
app.jwt.secret=${JWT_SECRET}
app.jwt.expiration-ms=3600000
app.jwt.refresh-expiration-ms=86400000

# OAuth2 (Google)
spring.security.oauth2.client.registration.google.client-id=${GOOGLE_CLIENT_ID}
spring.security.oauth2.client.registration.google.client-secret=${GOOGLE_CLIENT_SECRET}

```

## 🔐 Security Details

* **Password Storage**: Uses `BCryptPasswordEncoder` for hashing.
* **CORS**: Configured to allow cross-origin requests from specified front-end origins.
* **Token Logic**:
* **Access Token**: Short-lived, passed in `Authorization: Bearer <token>` header.
* **Refresh Token**: Long-lived, stored in the database to issue new access tokens.



## 🛠️ Getting Started

1. **Clone the repository**:
```bash
git clone <repository-url>

```


2. **Configure Database**: Ensure MySQL is running and create a database named `security`.
3. **Build the project**:
```bash
./mvnw clean install

```


4. **Run the application**:
```bash
./mvnw spring-boot:run

```

5. **Access Documentation**: Navigate to `http://localhost:8083/swagger-ui/index.html`.


