#!/bin/sh
# Read-only: check free endpoints + 402 challenge of each paid route. Usage: scripts/check-402.sh [base-url]
B=${1:-https://linkproof.zopip.com}
for p in / /health /openapi.json /.well-known/x402 /llms.txt /mcp/server-card /.well-known/mcp/server-card.json /.well-known/mcp.json; do curl -s -o /dev/null -w "GET $p %{http_code}\n" $B$p; done
for r in verify-answer verify-links verify-citations find-archive check-headers site-policies email-auth injection-scan wiki-summary license-detect ics-parse; do
  curl -s -D /tmp/h402 -o /dev/null -X POST $B/v1/$r
  printf "POST /v1/$r %s " "$(head -1 /tmp/h402 | tr -d '\r')"
  grep -i '^payment-required' /tmp/h402 | cut -d' ' -f2 | tr -d '\r' | base64 -d | python3 -c "
import json,sys;d=json.load(sys.stdin);a=d['accepts'][0];b=d['extensions']['bazaar'];print('amount',a['amount'],a['network'],a['payTo'][:10],'| resource',d['resource']['url'].split('/')[-1],'| bazaar input', b['info']['input']['method'], b['info']['input'].get('bodyType'), '| has output', 'output' in b['info'], '| schema', 'schema' in b, '| desc', d['resource'].get('description','')[:45])"
done
