# Project README: Security System

This repository contains a Spring Boot-based security system that implements robust authentication and authorization using JWT and OAuth2.

## Features

* **Role-Based Access Control (RBAC):** Manages user permissions through predefined roles like `USER` and `ADMIN`.
* **JWT Authentication:** Secure stateless authentication using JSON Web Tokens.
* **OAuth2 Integration:** Supports social login via Google.
* **Global Exception Handling:** Centralized management of errors, including resource not found, unauthorized access, and validation failures.
* **API Documentation:** Integrated with Swagger/OpenAPI for easy endpoint exploration.

## Technology Stack

* **Java 21**
* **Spring Boot 4.0.3**
* **Spring Security & OAuth2 Client**
* **Spring Data JPA**
* **MySQL Database**
* **Lombok** (to reduce boilerplate code)
* **jjwt** (for JWT implementation)

## Project Structure

* **Controllers:** Handle authentication requests (`/auth/register`, `/auth/login`).
* **Security Configuration:** Defines the security filter chain, session management, and endpoint permissions.
* **Services:** Contains business logic for user signup, login, and OAuth2 processing.
* **Entities:** JPA models, including the `User` entity which implements `UserDetails`.
* **Exceptions:** Custom exceptions and a global handler to provide consistent API responses.

## Setup and Configuration

1. **Database:** Ensure a MySQL instance is running and create a database named `security`.
2. **Environment Variables:** Configure the following environment variables for security and database access:
* `DB_USERNAME`: Database username (defaults to `root`).
* `DB_PASSWORD`: Your database password.
* `JWT_SECRET_KEY`: A secret key for signing JWTs.
* `GOOGLE_CLIENT_ID`: Google OAuth2 client ID.
* `GOOGLE_CLIENT_SECRET`: Google OAuth2 client secret.


3. **Build and Run:**
```bash
./mvnw clean install
./mvnw spring-boot:run

```



## API Endpoints

* **POST `/auth/register**`: Register a new user with username, password, and roles.
* **POST `/auth/login**`: Authenticate and receive a JWT.
* **OAuth2 Login**: Accessible via standard Spring Security OAuth2 endpoints (e.g., `/oauth2/authorization/google`).
* **Swagger UI**: View API documentation at `/swagger-ui.html`.
