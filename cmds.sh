curl -X POST http://127.0.0.1:5000/login -H 'Content-Type: application/json' -d '{"username": "test", "password": "test"}'
curl -X GET http://127.0.0.1:5000/pro -H "Authorization: Bearer $JWT"

curl -X POST  http://127.0.0.1:5000/login -H 'Content-Type: application/json' -d '{"username": "batman", "password": "password"}'

curl -X POST  http://127.0.0.1:5000/refresh -H "Authorization: Bearer $RJWT"

