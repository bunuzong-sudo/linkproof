#!/bin/sh
set -e
cd "$(dirname "$0")"
npx esbuild src/worker.ts --bundle --format=esm --platform=browser --conditions=worker,browser --target=es2022 --minify --external:url --external:'node:*' --outfile=dist/worker.js --log-level=warning
sed -i 's/from"url"/from"node:url"/' dist/worker.js
node make-deploy.js "${1:-testnet}"
