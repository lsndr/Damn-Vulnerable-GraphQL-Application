import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /graphql importPaste', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['ssrf', 'osi', 'graphql_introspection'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: "lsndr/Damn-Vulnerable-GraphQL-Application:master",
        databases: ["SQLAlchemy"],
        user_roles: {
          roles: ["admin"]
        }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/graphql`,
      body: {
        query: `mutation importPaste($host: String!, $port: Int, $path: String!, $scheme: String!) { importPaste(host: $host, port: $port, path: $path, scheme: $scheme) { result } }`,
        variables: {
          host: "icanhazip.com",
          port: 443,
          path: "/",
          scheme: "https"
        }
      },
      headers: { 'Content-Type': 'application/json' }
    });
});