defmodule ExOpenid4vcTest do
  use ExUnit.Case, async: true

  defp proof_key do
    JOSE.JWK.generate_key({:ec, "P-256"})
  end

  defp did_key_p256(jwk) do
    %{"x" => x, "y" => y} = public_jwk_map(jwk)

    x_bytes = Base.url_decode64!(x, padding: false)
    y_bytes = Base.url_decode64!(y, padding: false)

    "did:key:" <>
      ExDid.Base58Btc.encode(<<0x80, 0x24, 0x04, x_bytes::binary, y_bytes::binary>>)
  end

  defp public_jwk_map(jwk) do
    {_kty, jwk_map} = JOSE.JWK.to_public_map(jwk)
    jwk_map
  end

  defp did_jwk(jwk) do
    jwk
    |> public_jwk_map()
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
    |> then(&"did:jwk:#{&1}")
  end

  defp proof_jwt(claim_overrides \\ %{}, header_overrides \\ %{}, signing_jwk \\ proof_key()) do
    now = System.system_time(:second)

    header =
      Map.merge(
        %{
          "alg" => "ES256",
          "typ" => "openid4vci-proof+jwt",
          "jwk" => public_jwk_map(signing_jwk)
        },
        header_overrides
      )

    claims =
      Map.merge(
        %{
          "aud" => "https://issuer.delegate.local/credential",
          "nonce" => "nonce_123",
          "iat" => now
        },
        claim_overrides
      )

    JOSE.JWT.sign(signing_jwk, header, claims)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp rewrite_protected_header(jwt, updates) do
    [encoded_header, encoded_claims, encoded_signature] = String.split(jwt, ".", parts: 3)

    header =
      encoded_header
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()
      |> Map.merge(updates)

    rewritten_header =
      header
      |> Jason.encode!()
      |> Base.url_encode64(padding: false)

    rewritten_header <> "." <> encoded_claims <> "." <> encoded_signature
  end

  test "derives the metadata URL for a root credential issuer" do
    assert ExOpenid4vc.metadata_url("https://issuer.delegate.local") ==
             {:ok, "https://issuer.delegate.local/.well-known/openid-credential-issuer"}
  end

  test "derives the metadata URL for a path-based credential issuer" do
    assert ExOpenid4vc.metadata_url("https://issuer.delegate.local/organizations/org_123") ==
             {:ok,
              "https://issuer.delegate.local/.well-known/openid-credential-issuer/organizations/org_123"}
  end

  test "rejects non-https credential issuers" do
    assert ExOpenid4vc.metadata_url("http://issuer.delegate.local") ==
             {:error, :invalid_credential_issuer}
  end

  test "builds issuer metadata with credential configurations" do
    configuration =
      ExOpenid4vc.credential_configuration("jwt_vc_json", scope: "agent_delegation")

    metadata =
      ExOpenid4vc.issuer_metadata("https://issuer.delegate.local",
        authorization_servers: ["https://issuer.delegate.local"],
        nonce_endpoint: "https://issuer.delegate.local/nonce",
        credential_configurations_supported: %{
          "agent_delegation_jwt" => configuration
        }
      )

    assert metadata["credential_issuer"] == "https://issuer.delegate.local"
    assert metadata["credential_endpoint"] == "https://issuer.delegate.local/credential"
    assert metadata["authorization_servers"] == ["https://issuer.delegate.local"]

    assert metadata["credential_configurations_supported"]["agent_delegation_jwt"]["format"] ==
             "jwt_vc_json"
  end

  test "builds a credential configuration with proof and signing metadata" do
    configuration =
      ExOpenid4vc.credential_configuration("jwt_vc_json",
        scope: "agent_delegation",
        cryptographic_binding_methods_supported: ["did:key", "did:web"],
        credential_signing_alg_values_supported: ["ES256", "EdDSA"],
        proof_types_supported: %{
          "jwt" => %{
            "proof_signing_alg_values_supported" => ["ES256", "EdDSA"]
          }
        },
        credential_definition: %{
          "type" => ["VerifiableCredential", "AgentDelegationCredential"]
        }
      )

    assert configuration["scope"] == "agent_delegation"
    assert configuration["cryptographic_binding_methods_supported"] == ["did:key", "did:web"]
    assert configuration["credential_signing_alg_values_supported"] == ["ES256", "EdDSA"]

    assert configuration["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"] ==
             [
               "ES256",
               "EdDSA"
             ]
  end

  test "builds a credential offer with both authorization code and pre-authorized flows" do
    offer =
      ExOpenid4vc.credential_offer(
        "https://issuer.delegate.local",
        ["agent_delegation_jwt"],
        authorization_code:
          ExOpenid4vc.authorization_code_grant(
            issuer_state: "issuer_state_123",
            authorization_server: "https://issuer.delegate.local"
          ),
        pre_authorized_code:
          ExOpenid4vc.pre_authorized_code_grant("preauth_123",
            interval: 5,
            tx_code: %{"input_mode" => "numeric", "length" => 6}
          )
      )

    assert offer["credential_issuer"] == "https://issuer.delegate.local"
    assert offer["credential_configuration_ids"] == ["agent_delegation_jwt"]
    assert offer["grants"]["authorization_code"]["issuer_state"] == "issuer_state_123"

    assert offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"][
             "pre-authorized_code"
           ] == "preauth_123"
  end

  test "builds a nonce response" do
    assert ExOpenid4vc.nonce_response("nonce_123", 300) == %{
             "c_nonce" => "nonce_123",
             "c_nonce_expires_in" => 300
           }
  end

  test "builds a minimal credential request" do
    request =
      ExOpenid4vc.credential_request(
        "jwt_vc_json",
        "agent_delegation_jwt",
        %{"proof_type" => "jwt", "jwt" => "compact.jwt.value"},
        issuer_state: "issuer_state_123"
      )

    assert request["format"] == "jwt_vc_json"
    assert request["credential_configuration_id"] == "agent_delegation_jwt"
    assert request["issuer_state"] == "issuer_state_123"
  end

  test "builds a credential response envelope" do
    response =
      ExOpenid4vc.credential_response(
        "jwt_vc_json",
        "eyJhbGciOiJFUzI1NiJ9.credential.signature",
        c_nonce: "nonce_123",
        c_nonce_expires_in: 300
      )

    assert response["format"] == "jwt_vc_json"
    assert response["credential"] == "eyJhbGciOiJFUzI1NiJ9.credential.signature"
    assert response["c_nonce"] == "nonce_123"
  end

  test "parses a credential request with a credential configuration id and jwt proof" do
    assert {:ok, parsed} =
             ExOpenid4vc.parse_credential_request(
               %{
                 "credential_configuration_id" => "agent_delegation_jwt",
                 "proof" => %{
                   "proof_type" => "jwt",
                   "jwt" => "ey.ey.S"
                 }
               },
               credential_configurations: %{
                 "agent_delegation_jwt" => %{
                   "format" => "jwt_vc_json"
                 }
               },
               credential_configuration_ids: ["agent_delegation_jwt"],
               allowed_formats: ["jwt_vc_json"]
             )

    assert parsed["credential_configuration_id"] == "agent_delegation_jwt"
    assert parsed["credential_configuration"] == %{"format" => "jwt_vc_json"}
    assert parsed["proofs"] == %{"jwt" => ["ey.ey.S"]}
  end

  test "parses a credential request with credential response encryption" do
    encryption = %{
      "jwk" => %{
        "kty" => "EC",
        "crv" => "P-256",
        "x" => "KQb9h6A8Djq2mPRR9vywgq6Z9erjRzCQXDpUe1koXn4",
        "y" => "VGs0n6zkRgZNpmjQe7YQDdyCjTiMQuuLHfoalGoVYBo"
      },
      "alg" => "ECDH-ES",
      "enc" => "A256GCM"
    }

    assert {:ok, parsed} =
             ExOpenid4vc.parse_credential_request(
               %{
                 "credential_configuration_id" => "agent_delegation_jwt",
                 "proof" => %{
                   "proof_type" => "jwt",
                   "jwt" => "ey.ey.S"
                 },
                 "credential_response_encryption" => encryption
               },
               credential_configuration_ids: ["agent_delegation_jwt"]
             )

    refute Map.has_key?(parsed, "credential_response_encryption")
    assert parsed["credential_request"]["credential_response_encryption"] == encryption
  end

  test "rejects unsupported credential configuration ids while parsing" do
    assert {:error, :unsupported_credential_configuration} =
             ExOpenid4vc.parse_credential_request(
               %{
                 "credential_configuration_id" => "unknown",
                 "proof" => %{
                   "proof_type" => "jwt",
                   "jwt" => "ey.ey.S"
                 }
               },
               credential_configuration_ids: ["agent_delegation_jwt"]
             )
  end

  test "rejects unsupported formats while parsing" do
    assert {:error, :unsupported_format} =
             ExOpenid4vc.parse_credential_request(
               %{
                 "format" => "ldp_vc",
                 "proof" => %{
                   "proof_type" => "jwt",
                   "jwt" => "ey.ey.S"
                 }
               },
               allowed_formats: ["jwt_vc_json"]
             )
  end

  test "rejects credential requests that provide both proof and proofs" do
    assert {:error, :invalid_request} =
             ExOpenid4vc.parse_credential_request(%{
               "credential_configuration_id" => "agent_delegation_jwt",
               "proof" => %{
                 "proof_type" => "jwt",
                 "jwt" => "ey.ey.S"
               },
               "proofs" => %{
                 "jwt" => ["ey.ey.S"]
               }
             })
  end

  test "rejects malformed credential response encryption while parsing" do
    assert {:error, :invalid_credential_response_encryption} =
             ExOpenid4vc.parse_credential_request(%{
               "credential_configuration_id" => "agent_delegation_jwt",
               "proof" => %{
                 "proof_type" => "jwt",
                 "jwt" => "ey.ey.S"
               },
               "credential_response_encryption" => %{
                 "alg" => "ECDH-ES"
               }
             })
  end

  test "parses a credential request with a proofs jwt array" do
    assert {:ok, parsed} =
             ExOpenid4vc.parse_credential_request(%{
               "credential_configuration_id" => "agent_delegation_jwt",
               "proofs" => %{
                 "jwt" => ["ey.ey.S"]
               }
             })

    assert parsed["proofs"] == %{"jwt" => ["ey.ey.S"]}
  end

  test "rejects credential requests with multiple proof containers" do
    assert {:error, :invalid_proofs} =
             ExOpenid4vc.parse_credential_request(%{
               "credential_configuration_id" => "agent_delegation_jwt",
               "proofs" => %{
                 "jwt" => ["ey.ey.S"],
                 "attestation" => ["opaque"]
               }
             })
  end

  test "builds a deferred credential request" do
    assert ExOpenid4vc.deferred_credential_request("txn_123") == %{
             "transaction_id" => "txn_123"
           }
  end

  test "parses a deferred credential request" do
    assert {:ok, parsed} =
             ExOpenid4vc.parse_deferred_credential_request(%{
               "transaction_id" => "txn_123"
             })

    assert parsed["deferred_credential_request"] == %{"transaction_id" => "txn_123"}
  end

  test "builds a pending deferred credential response" do
    assert {:ok, response} =
             ExOpenid4vc.deferred_credential_response(
               transaction_id: "txn_123",
               interval: 15
             )

    assert response == %{
             "transaction_id" => "txn_123",
             "interval" => 15
           }
  end

  test "builds an issued deferred credential response" do
    assert {:ok, response} =
             ExOpenid4vc.deferred_credential_response(
               credentials: [%{"credential" => "eyJhbGciOiJFUzI1NiJ9.payload.signature"}]
             )

    assert response == %{
             "credentials" => [%{"credential" => "eyJhbGciOiJFUzI1NiJ9.payload.signature"}]
           }
  end

  test "rejects invalid deferred credential responses" do
    assert {:error, :invalid_deferred_credential_response} =
             ExOpenid4vc.deferred_credential_response(transaction_id: "txn_123")

    assert {:error, :invalid_deferred_credential_response} =
             ExOpenid4vc.deferred_credential_response(
               credentials: [%{"credential" => "eyJhbGciOiJFUzI1NiJ9.payload.signature"}],
               notification_id: "notification_123"
             )
  end

  test "rejects invalid deferred credential requests" do
    assert {:error, :invalid_deferred_credential_request} =
             ExOpenid4vc.parse_deferred_credential_request(%{})
  end

  test "builds and parses a notification request from the pinned fixture" do
    request_fixture =
      Path.expand("fixtures/spec/notification-request-valid.json", __DIR__)
      |> File.read!()
      |> Jason.decode!()

    assert {:ok, request} =
             ExOpenid4vc.notification_request(
               request_fixture["notification_id"],
               request_fixture["event"],
               event_description: request_fixture["event_description"]
             )

    assert request == request_fixture

    assert {:ok, %{"notification_request" => ^request_fixture}} =
             ExOpenid4vc.parse_notification_request(request)
  end

  test "builds a notification error response from the pinned fixture" do
    error_fixture =
      Path.expand("fixtures/spec/notification-error-valid.json", __DIR__)
      |> File.read!()
      |> Jason.decode!()

    assert {:ok, response} = ExOpenid4vc.notification_error_response(error_fixture["error"])
    assert response == error_fixture
  end

  test "rejects invalid notification inputs" do
    assert {:error, :invalid_notification_request} =
             ExOpenid4vc.notification_request("", "credential_accepted")

    assert {:error, :invalid_notification_request} =
             ExOpenid4vc.parse_notification_request(%{
               "notification_id" => "notification_123",
               "event" => "unsupported_event"
             })

    assert {:error, :invalid_notification_request} =
             ExOpenid4vc.notification_error_response("unsupported_error")
  end

  test "validates a JWT proof against audience and nonce" do
    assert {:ok, %{claims: claims, header: header}} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt()},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               max_age_seconds: 300
             )

    assert header["typ"] == "openid4vci-proof+jwt"
    assert claims["nonce"] == "nonce_123"
  end

  test "validates a JWT proof against a registered holder did:jwk" do
    signing_jwk = proof_key()

    assert {:ok, %{claims: claims}} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt(%{}, %{}, signing_jwk)},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               holder_did: did_jwk(signing_jwk)
             )

    assert claims["nonce"] == "nonce_123"
  end

  test "validates a JWT proof against a holder did:web when ex_did can normalize the DID document key material" do
    signing_jwk = proof_key()
    holder_did = "did:web:holder.delegate.local"

    assert {:ok, %{claims: claims}} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt(%{}, %{}, signing_jwk)},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               holder_did: holder_did,
               fetch_json: fn "https://holder.delegate.local/.well-known/did.json" ->
                 {:ok,
                  %{
                    "@context" => ["https://www.w3.org/ns/did/v1"],
                    "id" => holder_did,
                    "verificationMethod" => [
                      %{
                        "id" => holder_did <> "#key-1",
                        "type" => "JsonWebKey2020",
                        "controller" => holder_did,
                        "publicKeyJwk" => public_jwk_map(signing_jwk)
                      }
                    ],
                    "assertionMethod" => [holder_did <> "#key-1"]
                  }}
               end
             )

    assert claims["nonce"] == "nonce_123"
  end

  test "validates a JWT proof against a holder did:key when the DID document exposes multikey material" do
    signing_jwk = proof_key()
    holder_did = did_key_p256(signing_jwk)

    assert {:ok, %{claims: claims}} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt(%{}, %{}, signing_jwk)},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               holder_did: holder_did
             )

    assert claims["nonce"] == "nonce_123"
  end

  test "inspects a JWT proof without verifying it" do
    assert {:ok, %{header: header, claims: claims}} =
             ExOpenid4vc.inspect_jwt_proof(%{"proof_type" => "jwt", "jwt" => proof_jwt()})

    assert header["alg"] == "ES256"
    assert claims["aud"] == "https://issuer.delegate.local/credential"
  end

  test "rejects a JWT proof with the wrong nonce" do
    assert {:error, :invalid_proof_nonce} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt()},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_456"
             )
  end

  test "accepts a JWT proof when audience is provided as a list" do
    assert {:ok, %{claims: claims}} =
             ExOpenid4vc.validate_jwt_proof(
               %{
                 "proof_type" => "jwt",
                 "jwt" =>
                   proof_jwt(%{
                     "aud" => [
                       "https://issuer.delegate.local/credential",
                       "https://issuer.delegate.local"
                     ]
                   })
               },
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123"
             )

    assert is_list(claims["aud"])
  end

  test "rejects a JWT proof with the wrong typ" do
    assert {:error, :invalid_proof_typ} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt(%{}, %{"typ" => "JWT"})},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123"
             )
  end

  test "rejects JWT proofs issued too far in the future" do
    future_iat = System.system_time(:second) + 30

    assert {:error, :invalid_proof_iat} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt(%{"iat" => future_iat})},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               max_age_seconds: 300
             )
  end

  test "rejects JWT proofs with a missing typ header" do
    jwt =
      proof_jwt()
      |> rewrite_protected_header(%{"typ" => nil})

    assert {:error, :invalid_proof_typ} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => jwt},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123"
             )
  end

  test "rejects stale JWT proofs" do
    stale_iat = System.system_time(:second) - 301

    assert {:error, :invalid_proof_iat} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt(%{"iat" => stale_iat})},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               max_age_seconds: 300
             )
  end

  test "rejects a JWT proof with a bad signature" do
    signing_jwk = proof_key()
    other_jwk = proof_key()

    bad_signature_jwt =
      proof_jwt(
        %{},
        %{"jwk" => public_jwk_map(other_jwk)},
        signing_jwk
      )

    assert {:error, :invalid_proof_signature} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => bad_signature_jwt},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               max_age_seconds: 300
             )
  end

  test "rejects a JWT proof when the holder did:jwk does not match the proof key" do
    signing_jwk = proof_key()
    holder_jwk = proof_key()

    assert {:error, :holder_binding_mismatch} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt(%{}, %{}, signing_jwk)},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               holder_did: did_jwk(holder_jwk)
             )
  end

  test "rejects holder DID bindings when a supported DID resolves to a different key" do
    assert {:error, :holder_binding_mismatch} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt()},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               holder_did: "did:key:z6MkeXCES4onVW4up9Qgz1KRnZsKmGufcaZxF6Zpv2w5QwUK"
             )
  end

  test "rejects truly unsupported holder DID methods" do
    assert {:error, :invalid_holder_did} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => proof_jwt()},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               holder_did: "did:example:123"
             )
  end

  test "rejects unsupported signing algorithms before verification" do
    jwt =
      proof_jwt()
      |> rewrite_protected_header(%{"alg" => "RS256"})

    assert {:error, :unsupported_proof_alg} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => jwt},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               max_age_seconds: 300
             )
  end

  test "rejects proofs without key material" do
    jwt = proof_jwt(%{}, %{"jwk" => nil})

    assert {:error, :missing_proof_key} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => jwt},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123",
               max_age_seconds: 300
             )
  end

  test "rejects malformed proof payloads" do
    assert {:error, :invalid_proof_jwt} =
             ExOpenid4vc.validate_jwt_proof(
               %{"proof_type" => "jwt", "jwt" => "not-a-jwt"},
               expected_audience: "https://issuer.delegate.local/credential",
               expected_nonce: "nonce_123"
             )
  end
end
