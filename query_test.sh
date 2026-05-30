#!/bin/bash

TOKEN="dev-local-token-change-me"

#curl -s -X POST http://127.0.0.1:8080/ssh/connect \
#  -H "Authorization: Bearer $TOKEN" \
#  -H "Content-Type: application/json" \
#  -d '{"server":"lifeorient"}' | jq

#  curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
#  -H "Authorization: Bearer $TOKEN" \
#  -H "Content-Type: application/json" \
#  -d '{"server":"lifeorient","argv":["rm","-f","test.txt"]}' | jq

curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["ls","-la","/tmp"]}' | jq