import fs from 'node:fs/promises'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const fixturesRoot = path.resolve(__dirname, '../../test/fixtures/upstream')
const oracleScript = path.join(__dirname, 'oracle.js')

const configurations = {
  agent_delegation_jwt: {
    format: 'jwt_vc_json',
    scope: 'agent_delegation',
    cryptographic_binding_methods_supported: ['did:jwk'],
    credential_signing_alg_values_supported: ['ES256'],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: ['ES256'],
      },
    },
    credential_definition: {
      type: ['VerifiableCredential', 'AgentDelegationCredential'],
    },
  },
}

const cases = [
  {
    id: 'credential-offer-pre-authorized',
    operation: 'credential_offer',
    input: {
      credential_issuer: 'https://issuer.delegate.local',
      credential_configuration_ids: ['agent_delegation_jwt'],
      configurations,
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': 'preauth_123',
          interval: 5,
        },
      },
    },
  },
  {
    id: 'credential-offer-authorization-code',
    operation: 'credential_offer',
    input: {
      credential_issuer: 'https://issuer.delegate.local',
      credential_configuration_ids: ['agent_delegation_jwt'],
      configurations,
      grants: {
        authorization_code: {
          issuer_state: 'issuer_state_123',
        },
      },
    },
  },
  {
    id: 'credential-offer-both-grants-with-auth-server',
    operation: 'credential_offer',
    input: {
      credential_issuer: 'https://issuer.delegate.local',
      authorization_servers: ['https://issuer.delegate.local'],
      credential_configuration_ids: ['agent_delegation_jwt'],
      configurations,
      grants: {
        authorization_code: {
          issuer_state: 'issuer_state_123',
          authorization_server: 'https://issuer.delegate.local',
        },
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': 'preauth_123',
          authorization_server: 'https://issuer.delegate.local',
          interval: 5,
        },
      },
    },
  },
  {
    id: 'nonce-response-basic',
    operation: 'nonce_response',
    input: {
      c_nonce: 'nonce_123',
      c_nonce_expires_in: 300,
    },
  },
  {
    id: 'credential-response-basic',
    operation: 'credential_response',
    input: {
      format: 'jwt_vc_json',
      credential: 'eyJhbGciOiJFUzI1NiJ9.payload.signature',
      c_nonce: 'nonce_123',
      c_nonce_expires_in: 300,
    },
  },
  {
    id: 'parse-credential-request-basic',
    operation: 'parse_credential_request',
    input: {
      credential_issuer: 'https://issuer.delegate.local',
      credential_request: {
        credential_configuration_id: 'agent_delegation_jwt',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      configurations,
    },
  },
  {
    id: 'parse-credential-request-with-encryption',
    operation: 'parse_credential_request',
    input: {
      credential_issuer: 'https://issuer.delegate.local',
      credential_request: {
        credential_configuration_id: 'agent_delegation_jwt',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
        credential_response_encryption: {
          jwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'KQb9h6A8Djq2mPRR9vywgq6Z9erjRzCQXDpUe1koXn4',
            y: 'VGs0n6zkRgZNpmjQe7YQDdyCjTiMQuuLHfoalGoVYBo',
          },
          alg: 'ECDH-ES',
          enc: 'A256GCM',
        },
      },
      configurations,
    },
  },
  {
    id: 'deferred-credential-response-pending',
    operation: 'deferred_credential_response',
    input: {
      transaction_id: 'txn_123',
      interval: 15,
    },
  },
  {
    id: 'deferred-credential-response-issued',
    operation: 'deferred_credential_response',
    input: {
      credentials: [
        {
          credential: 'eyJhbGciOiJFUzI1NiJ9.payload.signature',
        },
      ],
    },
  },
  {
    id: 'parse-deferred-credential-request-basic',
    operation: 'parse_deferred_credential_request',
    input: {
      deferred_credential_request: {
        transaction_id: 'txn_123',
      },
    },
  },
  {
    id: 'parse-deferred-credential-request-with-encryption',
    operation: 'parse_deferred_credential_request',
    input: {
      deferred_credential_request: {
        transaction_id: 'txn_123',
        credential_response_encryption: {
          jwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'KQb9h6A8Djq2mPRR9vywgq6Z9erjRzCQXDpUe1koXn4',
            y: 'VGs0n6zkRgZNpmjQe7YQDdyCjTiMQuuLHfoalGoVYBo',
          },
          alg: 'ECDH-ES',
          enc: 'A256GCM',
        },
      },
    },
  },
]

await main()

async function main() {
  const channel = process.argv[2] ?? 'released'

  if (channel !== 'released') {
    throw new Error(`unsupported channel: ${channel}`)
  }

  const channelDir = path.join(fixturesRoot, channel)
  await fs.rm(path.join(channelDir, 'cases'), { recursive: true, force: true })
  await fs.mkdir(path.join(channelDir, 'cases'), { recursive: true })

  const manifestCases = []

  for (const testCase of cases) {
    const recorded = invokeOracle(testCase.operation, testCase.input)
    const file = `${testCase.id}.json`

    await fs.writeFile(
      path.join(channelDir, 'cases', file),
      JSON.stringify(
        {
          id: testCase.id,
          operation: testCase.operation,
          input: testCase.input,
          oracle: recorded,
        },
        null,
        2
      ) + '\n'
    )

    manifestCases.push({
      id: testCase.id,
      operation: testCase.operation,
      file,
    })
  }

  const manifest = {
    schemaVersion: 1,
    advisory: false,
    channel: 'released',
    generatedAt: new Date().toISOString(),
    oracle: {
      package: '@openid4vc/openid4vci',
      version: '0.4.5',
    },
    cases: manifestCases,
  }

  await fs.writeFile(path.join(channelDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n')
}

function invokeOracle(operation, input) {
  return JSON.parse(
    execFileSync(process.execPath, [oracleScript, operation, JSON.stringify(input)], {
      cwd: __dirname,
      encoding: 'utf8',
    })
  )
}
