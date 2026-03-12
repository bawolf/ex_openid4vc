defmodule ExOpenid4vc.SpecFixtureTest do
  use ExUnit.Case, async: true

  @fixtures_root Path.expand("fixtures/spec", __DIR__)
  @expected_audience "https://issuer.delegate.local/credential"
  @expected_nonce "nonce_123"

  test "spec fixture corpus matches current outputs" do
    manifest = load_json(Path.join(@fixtures_root, "manifest.json"))

    for test_case <- manifest["cases"] do
      recorded = load_json(Path.join([@fixtures_root, test_case["file"]]))
      run_operation(test_case["operation"], recorded)
    end
  end

  defp run_operation("notification_request", recorded) do
    assert {:ok, request} =
             ExOpenid4vc.notification_request(
               recorded["notification_id"],
               recorded["event"],
               event_description: recorded["event_description"]
             )

    assert request == recorded

    assert {:ok, %{"notification_request" => ^recorded}} =
             ExOpenid4vc.parse_notification_request(request)
  end

  defp run_operation("notification_error_response", recorded) do
    assert {:ok, response} = ExOpenid4vc.notification_error_response(recorded["error"])
    assert response == recorded
  end

  defp run_operation("proof_validation_cases", %{"cases" => cases}) when is_list(cases) do
    for test_case <- cases do
      assert_proof_case(test_case)
    end
  end

  defp assert_proof_case(%{"expected" => "ok"} = test_case) do
    {proof, opts} = proof_fixture_inputs(test_case)

    assert {:ok, _result} = ExOpenid4vc.validate_jwt_proof(proof, opts)
  end

  defp assert_proof_case(%{"expected" => expected} = test_case) do
    {proof, opts} = proof_fixture_inputs(test_case)

    expected_atom = String.to_atom(expected)

    assert {:error, ^expected_atom} = ExOpenid4vc.validate_jwt_proof(proof, opts)
  end

  defp proof_fixture_inputs(test_case) do
    signing_jwk = proof_key()

    proof =
      case Map.get(test_case, "raw_jwt") do
        nil ->
          header_overrides = Map.get(test_case, "header_overrides", %{})

          %{
            "proof_type" => "jwt",
            "jwt" =>
              proof_jwt(
                normalize_claim_overrides(Map.get(test_case, "claim_overrides", %{})),
                signing_jwk
              )
              |> maybe_rewrite_protected_header(header_overrides)
          }

        raw_jwt ->
          %{"proof_type" => "jwt", "jwt" => raw_jwt}
      end

    opts =
      [
        expected_audience: @expected_audience,
        expected_nonce: @expected_nonce,
        max_age_seconds: 300
      ]
      |> Keyword.merge(holder_binding_opts(Map.get(test_case, "holder_binding"), signing_jwk))

    {proof, opts}
  end

  defp holder_binding_opts(nil, _signing_jwk), do: []

  defp holder_binding_opts("did_jwk_match", signing_jwk),
    do: [holder_did: did_jwk(signing_jwk)]

  defp holder_binding_opts("did_jwk_mismatch", _signing_jwk),
    do: [holder_did: did_jwk(proof_key())]

  defp holder_binding_opts("did_key_match", signing_jwk),
    do: [holder_did: did_key_p256(signing_jwk)]

  defp holder_binding_opts("did_key_mismatch", _signing_jwk),
    do: [holder_did: "did:key:z6MkeXCES4onVW4up9Qgz1KRnZsKmGufcaZxF6Zpv2w5QwUK"]

  defp holder_binding_opts("did_web_match", signing_jwk) do
    holder_did = "did:web:holder.delegate.local"

    [
      holder_did: holder_did,
      fetch_json: fn "https://holder.delegate.local/.well-known/did.json" ->
        {:ok, did_web_document(holder_did, signing_jwk)}
      end
    ]
  end

  defp holder_binding_opts("did_web_mismatch", _signing_jwk) do
    holder_did = "did:web:holder.delegate.local"
    mismatched_jwk = proof_key()

    [
      holder_did: holder_did,
      fetch_json: fn "https://holder.delegate.local/.well-known/did.json" ->
        {:ok, did_web_document(holder_did, mismatched_jwk)}
      end
    ]
  end

  defp holder_binding_opts("unsupported_holder", _signing_jwk),
    do: [holder_did: "did:example:123"]

  defp did_web_document(holder_did, signing_jwk) do
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
    }
  end

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

  defp proof_jwt(claim_overrides, signing_jwk) do
    now = System.system_time(:second)

    header = %{
      "alg" => "ES256",
      "typ" => "openid4vci-proof+jwt",
      "jwk" => public_jwk_map(signing_jwk)
    }

    claims =
      Map.merge(
        %{
          "aud" => @expected_audience,
          "nonce" => @expected_nonce,
          "iat" => now
        },
        claim_overrides
      )

    JOSE.JWT.sign(signing_jwk, header, claims)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp maybe_rewrite_protected_header(jwt, overrides) when overrides == %{}, do: jwt

  defp maybe_rewrite_protected_header(jwt, overrides) when is_map(overrides) do
    [encoded_header, encoded_claims, encoded_signature] = String.split(jwt, ".", parts: 3)

    header =
      encoded_header
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()
      |> Map.merge(overrides)

    rewritten_header =
      header
      |> Jason.encode!()
      |> Base.url_encode64(padding: false)

    rewritten_header <> "." <> encoded_claims <> "." <> encoded_signature
  end

  defp normalize_claim_overrides(%{"iat_offset_seconds" => offset} = overrides)
       when is_integer(offset) do
    overrides
    |> Map.delete("iat_offset_seconds")
    |> Map.put("iat", System.system_time(:second) + offset)
  end

  defp normalize_claim_overrides(overrides), do: overrides

  defp load_json(path) do
    path
    |> File.read!()
    |> Jason.decode!()
  end
end
