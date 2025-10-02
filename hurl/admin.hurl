# Setup - Create Admin
POST http://localhost:3000/api/login
Content-Type: application/json
{
  "identity": "{{admin_email}}",
  "password": "{{admin_password}}"
}
HTTP 200
[Captures]
token: jsonpath "$['token']"

# Test - Create user without group
POST http://localhost:3000/api/admin/user
Content-Type: application/json
Authorization: Bearer {{token}}
{
  "email": "{{newUuid}}@example.com",
  "username": "{{group_user_username}}{{newDate}}",
  "password": "{{group_user_password}}"
}
HTTP 201
[Asserts]
# should belong to user group by default
jsonpath "$.groups" count == 1
jsonpath "$.groups[0]" == "users"

# Test - Create user with invalid group
POST http://localhost:3000/api/admin/user
Content-Type: application/json
Authorization: Bearer {{token}}
{
  "email": "{{newUuid}}@example.com",
  "username": "{{group_user_username}}{{newDate}}",
  "password": "{{group_user_password}}",
  "groups": ["invalid"]
}
HTTP 400
`invalid group specified: \`invalid\``

# Test - Create user with valid group
POST http://localhost:3000/api/admin/user
Content-Type: application/json
Authorization: Bearer {{token}}
{
  "email": "{{newUuid}}@example.com",
  "username": "{{group_user_username}}{{newDate}}",
  "password": "{{group_user_password}}",
  "groups": ["superadmin"]
}
HTTP 201
[Asserts]
# should have `superadmin` group
jsonpath "$.groups" count == 1
jsonpath "$.groups[0]" == "superadmin"