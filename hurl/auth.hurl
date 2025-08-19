# Register User
POST http://localhost:3000/api/register
Content-Type: application/json

{
  "email": "{{email}}",
  "username": "{{username}}",
  "password": "{{password}}"
}

# Login with this user
POST http://localhost:3000/api/login
Content-Type: application/json

{
  "identity": "{{email}}",
  "password": "{{password}}"
}
