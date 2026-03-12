defmodule ExOpenid4vc do
  @moduledoc """
  Minimal OpenID4VCI boundary for Elixir.

  This package currently focuses on:

  - Credential Issuer metadata URL derivation
  - Credential Issuer metadata construction
  - Credential configuration construction
  - Credential Offer construction
  - JWT proof parsing and validation
  """

  @proof_jwt_typ "openid4vci-proof+jwt"
  @default_proof_max_age_seconds 300
  @default_proof_signing_algs ["ES256", "EdDSA"]

  @spec metadata_url(String.t()) :: {:ok, String.t()} | {:error, atom()}
  def metadata_url(credential_issuer) when is_binary(credential_issuer) do
    with %URI{scheme: "https", host: host} = uri when is_binary(host) <-
           URI.parse(credential_issuer) do
      path =
        case uri.path do
          nil -> ""
          "/" -> ""
          other -> other
        end

      metadata_uri = %URI{
        scheme: "https",
        host: host,
        port: uri.port,
        path: "/.well-known/openid-credential-issuer" <> path
      }

      {:ok, URI.to_string(metadata_uri)}
    else
      _ -> {:error, :invalid_credential_issuer}
    end
  end

  @spec credential_configuration(String.t(), keyword()) :: map()
  def credential_configuration(format, opts \\ []) when is_binary(format) do
    base = %{
      "format" => format
    }

    base
    |> maybe_put("scope", opts[:scope])
    |> maybe_put(
      "cryptographic_binding_methods_supported",
      opts[:cryptographic_binding_methods_supported]
    )
    |> maybe_put(
      "credential_signing_alg_values_supported",
      opts[:credential_signing_alg_values_supported]
    )
    |> maybe_put("proof_types_supported", opts[:proof_types_supported])
    |> maybe_put("credential_definition", opts[:credential_definition])
    |> maybe_put("display", opts[:display])
    |> maybe_put("doctype", opts[:doctype])
    |> maybe_put("claims", opts[:claims])
    |> maybe_put("vct", opts[:vct])
  end

  @spec issuer_metadata(String.t(), keyword()) :: map()
  def issuer_metadata(credential_issuer, opts \\ []) when is_binary(credential_issuer) do
    credential_endpoint =
      Keyword.get(opts, :credential_endpoint, join_url(credential_issuer, "/credential"))

    authorization_servers = Keyword.get(opts, :authorization_servers)
    nonce_endpoint = Keyword.get(opts, :nonce_endpoint)
    deferred_credential_endpoint = Keyword.get(opts, :deferred_credential_endpoint)
    notification_endpoint = Keyword.get(opts, :notification_endpoint)

    credential_configurations_supported =
      Keyword.get(opts, :credential_configurations_supported, %{})

    signed_metadata = Keyword.get(opts, :signed_metadata)

    %{
      "credential_issuer" => credential_issuer,
      "credential_endpoint" => credential_endpoint,
      "credential_configurations_supported" => credential_configurations_supported
    }
    |> maybe_put("authorization_servers", authorization_servers)
    |> maybe_put("nonce_endpoint", nonce_endpoint)
    |> maybe_put("deferred_credential_endpoint", deferred_credential_endpoint)
    |> maybe_put("notification_endpoint", notification_endpoint)
    |> maybe_put("signed_metadata", signed_metadata)
  end

  @spec authorization_code_grant(keyword()) :: map()
  def authorization_code_grant(opts \\ []) do
    %{}
    |> maybe_put("issuer_state", opts[:issuer_state])
    |> maybe_put("authorization_server", opts[:authorization_server])
  end

  @spec pre_authorized_code_grant(String.t(), keyword()) :: map()
  def pre_authorized_code_grant(pre_authorized_code, opts \\ [])
      when is_binary(pre_authorized_code) do
    %{
      "pre-authorized_code" => pre_authorized_code
    }
    |> maybe_put("tx_code", opts[:tx_code])
    |> maybe_put("authorization_server", opts[:authorization_server])
    |> maybe_put("interval", opts[:interval])
  end

  @spec credential_offer(String.t(), [String.t()], keyword()) :: map()
  def credential_offer(credential_issuer, credential_configuration_ids, opts \\ [])
      when is_binary(credential_issuer) and is_list(credential_configuration_ids) do
    %{
      "credential_issuer" => credential_issuer,
      "credential_configuration_ids" => credential_configuration_ids,
      "grants" => grants(opts)
    }
    |> maybe_put("credentials", opts[:credentials])
  end

  @spec nonce_response(String.t(), non_neg_integer()) :: map()
  def nonce_response(c_nonce, c_nonce_expires_in)
      when is_binary(c_nonce) and is_integer(c_nonce_expires_in) and c_nonce_expires_in >= 0 do
    %{
      "c_nonce" => c_nonce,
      "c_nonce_expires_in" => c_nonce_expires_in
    }
  end

  @spec credential_request(String.t(), String.t(), map(), keyword()) :: map()
  def credential_request(format, credential_configuration_id, proof, opts \\ [])
      when is_binary(format) and is_binary(credential_configuration_id) and is_map(proof) do
    %{
      "format" => format,
      "credential_configuration_id" => credential_configuration_id,
      "proof" => proof
    }
    |> maybe_put("issuer_state", opts[:issuer_state])
    |> maybe_put("pre_authorized_code", opts[:pre_authorized_code])
  end

  @spec credential_response(String.t(), String.t() | map(), keyword()) :: map()
  def credential_response(format, credential, opts \\ [])
      when is_binary(format) and (is_binary(credential) or is_map(credential)) do
    %{
      "format" => format,
      "credential" => credential
    }
    |> maybe_put("c_nonce", opts[:c_nonce])
    |> maybe_put("c_nonce_expires_in", opts[:c_nonce_expires_in])
  end

  @type credential_request_parse_error ::
          :invalid_request
          | :unsupported_format
          | :unsupported_credential_configuration
          | :invalid_proof_type
          | :invalid_proof_jwt
          | :invalid_proofs
          | :invalid_credential_response_encryption

  @spec parse_credential_request(map(), keyword()) ::
          {:ok, map()} | {:error, credential_request_parse_error()}
  def parse_credential_request(request, opts \\ []) when is_map(request) and is_list(opts) do
    allowed_formats = Keyword.get(opts, :allowed_formats, [])
    credential_configuration_ids = Keyword.get(opts, :credential_configuration_ids, [])
    credential_configurations = Keyword.get(opts, :credential_configurations, %{})

    with :ok <- validate_allowed_format(request, allowed_formats),
         :ok <- validate_allowed_credential_configuration(request, credential_configuration_ids),
         {:ok, selector} <- parse_request_selector(request, credential_configurations),
         {:ok, proofs} <- parse_request_proofs(request),
         {:ok, _credential_response_encryption} <- parse_credential_response_encryption(request) do
      {:ok,
       %{
         "credential_request" => request
       }
       |> maybe_put("format", selector[:format])
       |> maybe_put("credential_configuration", selector[:credential_configuration])
       |> maybe_put("credential_configuration_id", selector[:credential_configuration_id])
       |> maybe_put("credential_identifier", selector[:credential_identifier])
       |> maybe_put("proofs", proofs)}
    end
  end

  @spec deferred_credential_request(String.t(), keyword()) :: map()
  def deferred_credential_request(transaction_id, opts \\ [])
      when is_binary(transaction_id) and transaction_id != "" do
    %{
      "transaction_id" => transaction_id
    }
    |> maybe_put("credential_response_encryption", opts[:credential_response_encryption])
  end

  @type deferred_credential_request_parse_error ::
          :invalid_deferred_credential_request | :invalid_credential_response_encryption

  @spec parse_deferred_credential_request(map()) ::
          {:ok, map()} | {:error, deferred_credential_request_parse_error()}
  def parse_deferred_credential_request(request) when is_map(request) do
    with {:ok, transaction_id} <- fetch_transaction_id(request),
         {:ok, _credential_response_encryption} <- parse_credential_response_encryption(request) do
      {:ok,
       %{
         "deferred_credential_request" => Map.put(request, "transaction_id", transaction_id)
       }}
    end
  end

  @type deferred_credential_response_error :: :invalid_deferred_credential_response

  @spec deferred_credential_response(keyword()) ::
          {:ok, map()} | {:error, deferred_credential_response_error()}
  def deferred_credential_response(opts) when is_list(opts) do
    credentials = Keyword.get(opts, :credentials)
    transaction_id = Keyword.get(opts, :transaction_id)
    interval = Keyword.get(opts, :interval)
    notification_id = Keyword.get(opts, :notification_id)

    cond do
      is_list(credentials) and credentials != [] and is_nil(transaction_id) and
          is_nil(notification_id) ->
        {:ok,
         %{}
         |> maybe_put("credentials", credentials)}

      is_binary(transaction_id) and transaction_id != "" and is_integer(interval) and interval > 0 and
        is_nil(credentials) and is_nil(notification_id) ->
        {:ok,
         %{
           "transaction_id" => transaction_id,
           "interval" => interval
         }}

      true ->
        {:error, :invalid_deferred_credential_response}
    end
  end

  @notification_events [
    "credential_accepted",
    "credential_failure",
    "credential_deleted"
  ]

  @notification_error_codes [
    "invalid_notification_id",
    "invalid_notification_request"
  ]

  @spec notification_request(String.t(), String.t(), keyword()) ::
          {:ok, map()} | {:error, :invalid_notification_request}
  def notification_request(notification_id, event, opts \\ [])

  def notification_request(notification_id, event, opts)
      when is_binary(notification_id) and is_binary(event) and is_list(opts) do
    if notification_id != "" and event in @notification_events do
      {:ok,
       %{
         "notification_id" => notification_id,
         "event" => event
       }
       |> maybe_put("event_description", opts[:event_description])}
    else
      {:error, :invalid_notification_request}
    end
  end

  def notification_request(_notification_id, _event, _opts),
    do: {:error, :invalid_notification_request}

  @spec parse_notification_request(map()) ::
          {:ok, map()} | {:error, :invalid_notification_request}
  def parse_notification_request(
        %{"notification_id" => notification_id, "event" => event} = request
      )
      when is_binary(notification_id) and notification_id != "" and
             is_binary(event) and event in @notification_events do
    {:ok, %{"notification_request" => request}}
  end

  def parse_notification_request(_request), do: {:error, :invalid_notification_request}

  @spec notification_error_response(String.t()) ::
          {:ok, map()} | {:error, :invalid_notification_request}
  def notification_error_response(error_code) when error_code in @notification_error_codes do
    {:ok, %{"error" => error_code}}
  end

  def notification_error_response(_error_code), do: {:error, :invalid_notification_request}

  @spec inspect_jwt_proof(map()) ::
          {:ok, %{header: map(), claims: map(), jwt: String.t()}} | {:error, atom()}
  def inspect_jwt_proof(%{"proof_type" => "jwt", "jwt" => jwt}) when is_binary(jwt) do
    with {:ok, header, claims} <- decode_jwt(jwt) do
      {:ok, %{header: header, claims: claims, jwt: jwt}}
    end
  end

  def inspect_jwt_proof(%{"proof_type" => "jwt"}), do: {:error, :invalid_proof_jwt}

  def inspect_jwt_proof(%{"proof_type" => proof_type}) when proof_type != "jwt",
    do: {:error, :invalid_proof_type}

  def inspect_jwt_proof(_proof), do: {:error, :invalid_proof_type}

  @spec validate_jwt_proof_claims(map(), keyword()) :: :ok | {:error, atom()}
  def validate_jwt_proof_claims(%{header: header, claims: claims}, opts) when is_list(opts) do
    expected_nonce = Keyword.get(opts, :expected_nonce)
    expected_audience = Keyword.get(opts, :expected_audience)
    max_age_seconds = Keyword.get(opts, :max_age_seconds, @default_proof_max_age_seconds)
    now = Keyword.get(opts, :now, System.system_time(:second))
    allowed_algs = Keyword.get(opts, :allowed_algs, @default_proof_signing_algs)

    with :ok <- validate_header(header, allowed_algs),
         :ok <- validate_audience(claims, expected_audience),
         :ok <- validate_nonce(claims, expected_nonce),
         :ok <- validate_iat(claims, now, max_age_seconds) do
      :ok
    end
  end

  @spec verify_jwt_proof_signature(map(), keyword()) :: :ok | {:error, atom()}
  def verify_jwt_proof_signature(%{header: header, jwt: jwt}, opts) when is_list(opts) do
    with {:ok, alg} <- fetch_alg(header),
         {:ok, jwk} <- resolve_verification_jwk(header, opts),
         {true, _verified_jwt, _verified_jws} <- JOSE.JWT.verify_strict(jwk, [alg], jwt) do
      :ok
    else
      {:error, _} = error ->
        error

      {false, _verified_jwt, _verified_jws} ->
        {:error, :invalid_proof_signature}

      _ ->
        {:error, :invalid_proof_signature}
    end
  end

  @spec validate_jwt_proof(map(), keyword()) ::
          {:ok, %{header: map(), claims: map(), jwt: String.t()}} | {:error, atom()}
  def validate_jwt_proof(%{"proof_type" => "jwt"} = proof, opts) when is_list(opts) do
    with {:ok, inspected} <- inspect_jwt_proof(proof),
         :ok <- validate_jwt_proof_claims(inspected, opts),
         :ok <- verify_jwt_proof_signature(inspected, opts),
         :ok <- validate_holder_binding(inspected, opts) do
      {:ok, inspected}
    end
  end

  def validate_jwt_proof(%{"proof_type" => "jwt"} = _proof, _opts),
    do: {:error, :invalid_proof_jwt}

  def validate_jwt_proof(%{"proof_type" => proof_type}, _opts) when proof_type != "jwt",
    do: {:error, :invalid_proof_type}

  def validate_jwt_proof(_proof, _opts), do: {:error, :invalid_proof_type}

  defp grants(opts) do
    []
    |> maybe_add_grant("authorization_code", opts[:authorization_code])
    |> maybe_add_grant(
      "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      opts[:pre_authorized_code]
    )
    |> Map.new()
  end

  defp maybe_add_grant(grants, _name, nil), do: grants
  defp maybe_add_grant(grants, name, grant), do: [{name, grant} | grants]

  defp fetch_transaction_id(%{"transaction_id" => transaction_id})
       when is_binary(transaction_id) and transaction_id != "" do
    {:ok, transaction_id}
  end

  defp fetch_transaction_id(_request), do: {:error, :invalid_deferred_credential_request}

  defp parse_request_selector(
         %{"credential_configuration_id" => credential_configuration_id},
         credential_configurations
       )
       when is_binary(credential_configuration_id) and credential_configuration_id != "" do
    {:ok,
     %{
       credential_configuration_id: credential_configuration_id,
       credential_configuration: Map.get(credential_configurations, credential_configuration_id)
     }}
  end

  defp parse_request_selector(
         %{"credential_identifier" => credential_identifier},
         _credential_configurations
       )
       when is_binary(credential_identifier) and credential_identifier != "" do
    {:ok, %{credential_identifier: credential_identifier}}
  end

  defp parse_request_selector(%{"format" => format} = request, _credential_configurations)
       when is_binary(format) and format != "" do
    {:ok, %{format: format_specific_request(request, format)}}
  end

  defp parse_request_selector(_request, _credential_configurations),
    do: {:error, :invalid_request}

  defp validate_allowed_format(%{"format" => format}, allowed_formats)
       when is_binary(format) and format != "" and allowed_formats != [] do
    if format in allowed_formats, do: :ok, else: {:error, :unsupported_format}
  end

  defp validate_allowed_format(_request, _allowed_formats), do: :ok

  defp validate_allowed_credential_configuration(
         %{"credential_configuration_id" => credential_configuration_id},
         credential_configuration_ids
       )
       when is_binary(credential_configuration_id) and credential_configuration_id != "" and
              credential_configuration_ids != [] do
    if credential_configuration_id in credential_configuration_ids do
      :ok
    else
      {:error, :unsupported_credential_configuration}
    end
  end

  defp validate_allowed_credential_configuration(_request, _credential_configuration_ids), do: :ok

  defp parse_request_proofs(%{"proof" => _proof, "proofs" => _proofs}),
    do: {:error, :invalid_request}

  defp parse_request_proofs(%{"proof" => %{"proof_type" => "jwt", "jwt" => jwt}})
       when is_binary(jwt) and jwt != "" do
    {:ok, %{"jwt" => [jwt]}}
  end

  defp parse_request_proofs(%{"proof" => %{"proof_type" => "jwt"}}),
    do: {:error, :invalid_proof_jwt}

  defp parse_request_proofs(%{"proof" => %{"proof_type" => proof_type}})
       when is_binary(proof_type) and proof_type != "jwt" do
    {:error, :invalid_proof_type}
  end

  defp parse_request_proofs(%{"proof" => proof}) when is_map(proof),
    do: {:error, :invalid_proof_type}

  defp parse_request_proofs(%{"proofs" => proofs}) when is_map(proofs) do
    case Map.to_list(proofs) do
      [{"jwt", proof_values}] when is_list(proof_values) ->
        if Enum.all?(proof_values, &(is_binary(&1) and &1 != "")) do
          {:ok, %{"jwt" => proof_values}}
        else
          {:error, :invalid_proof_jwt}
        end

      [_single_unknown] ->
        {:error, :invalid_proof_type}

      [] ->
        {:error, :invalid_proofs}

      _multiple ->
        {:error, :invalid_proofs}
    end
  end

  defp parse_request_proofs(_request), do: {:ok, nil}

  defp parse_credential_response_encryption(%{
         "credential_response_encryption" =>
           %{
             "jwk" => jwk,
             "alg" => alg,
             "enc" => enc
           } = encryption
       })
       when is_map(jwk) and is_binary(alg) and alg != "" and is_binary(enc) and enc != "" do
    if map_size(encryption) >= 3 do
      {:ok, encryption}
    else
      {:error, :invalid_credential_response_encryption}
    end
  end

  defp parse_credential_response_encryption(%{"credential_response_encryption" => _encryption}),
    do: {:error, :invalid_credential_response_encryption}

  defp parse_credential_response_encryption(_request), do: {:ok, nil}

  defp format_specific_request(request, format) do
    %{"format" => format}
    |> maybe_put("doctype", request["doctype"])
    |> maybe_put("credential_definition", request["credential_definition"])
    |> maybe_put("vct", request["vct"])
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, []), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp decode_jwt(jwt) do
    case String.split(jwt, ".", parts: 3) do
      [encoded_header, encoded_claims, encoded_signature]
      when encoded_header != "" and encoded_claims != "" and encoded_signature != "" ->
        with {:ok, header_json} <- url_decode(encoded_header),
             {:ok, claims_json} <- url_decode(encoded_claims),
             {:ok, header} <- decode_json_map(header_json, :invalid_proof_header),
             {:ok, claims} <- decode_json_map(claims_json, :invalid_proof_claims) do
          {:ok, header, claims}
        end

      _ ->
        {:error, :invalid_proof_jwt}
    end
  end

  defp validate_header(%{"typ" => @proof_jwt_typ, "alg" => alg}, allowed_algs)
       when is_binary(alg) and alg != "" and alg != "none" do
    if alg in allowed_algs, do: :ok, else: {:error, :unsupported_proof_alg}
  end

  defp validate_header(%{"typ" => typ}, _allowed_algs) when typ != @proof_jwt_typ,
    do: {:error, :invalid_proof_typ}

  defp validate_header(%{"alg" => "none"}, _allowed_algs), do: {:error, :invalid_proof_alg}

  defp validate_header(%{"alg" => alg}, _allowed_algs) when not is_binary(alg) or alg == "",
    do: {:error, :invalid_proof_alg}

  defp validate_header(_header, _allowed_algs), do: {:error, :invalid_proof_header}

  defp validate_audience(_claims, nil), do: :ok

  defp validate_audience(%{"aud" => aud}, expected_audience) when is_binary(aud) do
    if aud == expected_audience, do: :ok, else: {:error, :invalid_proof_audience}
  end

  defp validate_audience(%{"aud" => audiences}, expected_audience) when is_list(audiences) do
    if expected_audience in audiences, do: :ok, else: {:error, :invalid_proof_audience}
  end

  defp validate_audience(_claims, _expected_audience), do: {:error, :invalid_proof_audience}

  defp validate_nonce(_claims, nil), do: :ok

  defp validate_nonce(%{"nonce" => nonce}, expected_nonce) when is_binary(nonce) do
    if nonce == expected_nonce, do: :ok, else: {:error, :invalid_proof_nonce}
  end

  defp validate_nonce(_claims, _expected_nonce), do: {:error, :invalid_proof_nonce}

  defp validate_iat(%{"iat" => iat}, now, max_age_seconds) when is_integer(iat) do
    cond do
      iat > now + 5 -> {:error, :invalid_proof_iat}
      iat < now - max_age_seconds -> {:error, :invalid_proof_iat}
      true -> :ok
    end
  end

  defp validate_iat(_claims, _now, _max_age_seconds), do: {:error, :invalid_proof_iat}

  defp fetch_alg(%{"alg" => alg}) when is_binary(alg) and alg != "", do: {:ok, alg}
  defp fetch_alg(_header), do: {:error, :invalid_proof_alg}

  defp resolve_verification_jwk(header, opts) when is_list(opts) do
    case Keyword.fetch(opts, :jwk) do
      {:ok, jwk} ->
        normalize_jwk(jwk)

      :error ->
        resolve_verification_jwk_from_header(header)
    end
  end

  defp resolve_verification_jwk(header, _opts), do: resolve_verification_jwk_from_header(header)

  defp resolve_verification_jwk_from_header(%{"jwk" => nil}), do: {:error, :missing_proof_key}

  defp resolve_verification_jwk_from_header(%{"jwk" => jwk}) do
    normalize_jwk(jwk)
  end

  defp resolve_verification_jwk_from_header(_header), do: {:error, :missing_proof_key}

  defp normalize_jwk(%JOSE.JWK{} = jwk), do: {:ok, jwk}

  defp normalize_jwk(jwk) when is_map(jwk) do
    try do
      {:ok, JOSE.JWK.from_map(jwk)}
    rescue
      _ -> {:error, :invalid_proof_key}
    end
  end

  defp normalize_jwk(_jwk), do: {:error, :invalid_proof_key}

  defp validate_holder_binding(_inspected, opts) when not is_list(opts), do: :ok

  defp validate_holder_binding(%{header: header}, opts) do
    case Keyword.get(opts, :holder_did) do
      nil ->
        :ok

      holder_did when is_binary(holder_did) ->
        with {:ok, holder_jwk} <- resolve_holder_binding_jwk(holder_did, opts),
             {:ok, proof_jwk} <- resolve_verification_jwk(header, opts),
             true <- jwks_match?(holder_jwk, proof_jwk) do
          :ok
        else
          {:error, _} = error ->
            error

          false ->
            {:error, :holder_binding_mismatch}
        end

      _other ->
        {:error, :invalid_holder_did}
    end
  end

  defp resolve_holder_binding_jwk("did:" <> _ = holder_did, opts) do
    resolve_holder_binding_did_jwk(holder_did, opts)
  end

  defp resolve_holder_binding_jwk(_holder_did, _opts), do: {:error, :invalid_holder_did}

  defp resolve_holder_binding_did_jwk(holder_did, opts) do
    case ExDid.resolve(holder_did, did_resolver_opts(opts)) do
      %{did_document: %{} = document} ->
        document
        |> verification_method_jwks()
        |> List.first()
        |> case do
          %{} = jwk -> normalize_jwk(jwk)
          nil -> {:error, :unsupported_holder_did_method}
        end

      _ ->
        {:error, :invalid_holder_did}
    end
  end

  defp verification_method_jwks(document) when is_map(document) do
    cond do
      function_exported?(ExDid, :verification_method_jwks, 1) ->
        ExDid.verification_method_jwks(document)

      Code.ensure_loaded?(ExDid.Document) and
          function_exported?(ExDid.Document, :verification_method_jwks, 1) ->
        ExDid.Document.verification_method_jwks(document)

      true ->
        document
        |> ExDid.verification_methods()
        |> Enum.flat_map(fn
          %{"publicKeyJwk" => %{} = jwk} ->
            [jwk]

          %{"publicKeyMultibase" => multibase} when is_binary(multibase) ->
            normalize_multikey_jwk(multibase)

          _ ->
            []
        end)
    end
  end

  defp normalize_multikey_jwk(multibase) do
    cond do
      Code.ensure_loaded?(ExDid.KeyMulticodec) and
          function_exported?(ExDid.KeyMulticodec, :public_jwk, 1) ->
        case ExDid.KeyMulticodec.public_jwk(multibase) do
          {:ok, jwk} -> [jwk]
          {:error, _reason} -> []
        end

      true ->
        []
    end
  end

  defp did_resolver_opts(opts) do
    []
    |> maybe_put_opt(:fetch_json, Keyword.get(opts, :fetch_json))
    |> maybe_put_opt(:method_registry, Keyword.get(opts, :method_registry))
    |> maybe_put_opt(:validation, Keyword.get(opts, :did_validation))
  end

  defp maybe_put_opt(opts, _key, nil), do: opts
  defp maybe_put_opt(opts, key, value), do: Keyword.put(opts, key, value)

  defp jwks_match?(left, right) do
    canonical_jwk_map(left) == canonical_jwk_map(right)
  end

  defp canonical_jwk_map(%JOSE.JWK{} = jwk) do
    {_kty, jwk_map} = JOSE.JWK.to_public_map(jwk)
    canonical_jwk_map(jwk_map)
  end

  defp canonical_jwk_map(jwk) when is_map(jwk) do
    jwk
    |> Map.drop(["alg", "key_ops", "kid", "use", "ext"])
    |> Enum.sort()
    |> Map.new()
  end

  defp canonical_jwk_map(_jwk), do: %{}

  defp url_decode(segment) do
    Base.url_decode64(segment, padding: false)
    |> case do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_proof_jwt}
    end
  end

  defp decode_json_map(json, error) do
    case Jason.decode(json) do
      {:ok, %{} = map} -> {:ok, map}
      _ -> {:error, error}
    end
  end

  defp join_url(base_url, suffix) do
    base_url
    |> String.trim_trailing("/")
    |> Kernel.<>(suffix)
  end
end
