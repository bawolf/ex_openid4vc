import { Openid4vciIssuer, Openid4vciVersion } from '@openid4vc/openid4vci'

const issuer = new Openid4vciIssuer({
  callbacks: {
    generateRandom: async (size) => deterministicBytes(size),
  },
})

const operation = process.argv[2]
const input = JSON.parse(process.argv[3] ?? '{}')

try {
  const result = await run(operation, input)
  process.stdout.write(JSON.stringify({ ok: true, result }, null, 2))
} catch (error) {
  process.stdout.write(
    JSON.stringify(
      {
        ok: false,
        error: normalizeError(error),
      },
      null,
      2
    )
  )
  process.exitCode = 1
}

async function run(operation, input) {
  switch (operation) {
    case 'credential_offer':
      return normalizeCredentialOffer(
        await issuer.createCredentialOffer({
          issuerMetadata: issuerMetadata(input.credential_issuer, input.authorization_servers, input.configurations),
          credentialConfigurationIds: input.credential_configuration_ids,
          grants: input.grants ?? {},
          credentialOfferScheme: 'openid-credential-offer://',
        })
      )

    case 'nonce_response':
      return issuer.createNonceResponse({
        cNonce: input.c_nonce,
        cNonceExpiresIn: input.c_nonce_expires_in,
      })

    case 'credential_response':
      return normalizeCredentialResponse(
        await issuer.createCredentialResponse({
          credentialRequest: {
            format: {
              format: input.format,
            },
          },
          credential: input.credential,
          cNonce: input.c_nonce,
          cNonceExpiresInSeconds: input.c_nonce_expires_in,
        })
      )

    case 'parse_credential_request':
      return normalizeParsedCredentialRequest(
        issuer.parseCredentialRequest({
          issuerMetadata: issuerMetadataResult(
            input.credential_issuer,
            input.authorization_servers,
            input.configurations
          ),
          credentialRequest: input.credential_request,
        })
      )

    case 'deferred_credential_response':
      return normalizeDeferredCredentialResponse(
        await issuer.createDeferredCredentialResponse({
          ...(input.credentials ? { credentials: input.credentials } : {}),
          ...(input.transaction_id ? { transactionId: input.transaction_id } : {}),
          ...(input.interval ? { interval: input.interval } : {}),
          ...(input.notification_id ? { notificationId: input.notification_id } : {}),
        })
      )

    case 'parse_deferred_credential_request':
      return normalizeParsedDeferredCredentialRequest(
        issuer.parseDeferredCredentialRequest({
          deferredCredentialRequest: input.deferred_credential_request,
        })
      )

    default:
      throw new Error(`unsupported operation: ${operation}`)
  }
}

function issuerMetadata(credentialIssuer, authorizationServers, configurations) {
  return {
    credentialIssuer: {
      credential_issuer: credentialIssuer,
      credential_endpoint: `${credentialIssuer}/credential`,
      credential_configurations_supported: configurations,
      ...(authorizationServers ? { authorization_servers: authorizationServers } : {}),
    },
    originalDraftVersion: Openid4vciVersion.Draft15,
  }
}

function issuerMetadataResult(credentialIssuer, authorizationServers, configurations) {
  return {
    authorizationServers: authorizationServers ?? [],
    credentialIssuer: issuerMetadata(credentialIssuer, authorizationServers, configurations).credentialIssuer,
    knownCredentialConfigurations: configurations ?? {},
    originalDraftVersion: Openid4vciVersion.Draft15,
  }
}

function normalizeCredentialOffer(result) {
  return result.credentialOfferObject
}

function normalizeCredentialResponse(result) {
  return result
}

function normalizeParsedCredentialRequest(result) {
  return {
    ...(result.format ? { format: result.format } : {}),
    ...(result.proofs ? { proofs: result.proofs } : {}),
    ...(result.credentialConfiguration ? { credential_configuration: result.credentialConfiguration } : {}),
    ...(result.credentialConfigurationId
      ? { credential_configuration_id: result.credentialConfigurationId }
      : {}),
    ...(result.credentialIdentifier ? { credential_identifier: result.credentialIdentifier } : {}),
    ...(result.credentialRequest ? { credential_request: result.credentialRequest } : {}),
    ...(result.credentialResponseEncryption
      ? { credential_response_encryption: result.credentialResponseEncryption }
      : {}),
  }
}

function normalizeDeferredCredentialResponse(result) {
  return result.deferredCredentialResponse ?? result
}

function normalizeParsedDeferredCredentialRequest(result) {
  return {
    deferred_credential_request: result.deferredCredentialRequest,
  }
}

function normalizeError(error) {
  return {
    name: error?.name ?? 'Error',
    message: error?.message ?? String(error),
  }
}

function deterministicBytes(size) {
  const seed = Buffer.from('ex_openid4vc_upstream_parity')
  const output = Buffer.alloc(size)

  for (let index = 0; index < size; index += 1) {
    output[index] = seed[index % seed.length]
  }

  return Uint8Array.from(output)
}
