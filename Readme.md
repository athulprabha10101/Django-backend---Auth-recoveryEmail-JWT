Django Authentication and Email Reset Application
This repository contains a Django web application focused on providing robust user authentication features, including registration, login, and password reset functionality with email integration. It's designed as a comprehensive solution for managing user accounts and security within Django projects.

Key Features:
User Registration: Users can sign up with essential details like email, name, and password.
User Login: Secure login system that authenticates users based on their credentials.
Password Reset: Integrated email system allowing users to reset their forgotten passwords. This includes sending a password reset link to the user's registered email address.
Email Integration: Utilizes Django's email backend with Gmail SMTP for sending emails, including password reset links.
Custom Email Rendering: Uses a custom renderer to format JSON responses, especially for error handling.
Environment Variables for Security: Configuration settings, particularly for email, are securely managed using environment variables.
RESTful API Approach: Structured around Django REST Framework for efficient API design.
Robust Validation: Includes custom validation in serializers to ensure data integrity and security.

Technologies Used:
Django and Django REST Framework for the backend.
SMTP protocol with Gmail for email functionality.
Python dotenv for environment variable management.