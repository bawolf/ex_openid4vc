defmodule ExOpenid4vc.UpstreamLivePropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  @live_oracle_enabled System.get_env("EX_OPENID4VC_LIVE_ORACLE") == "1" and
                         File.exists?(
                           Path.expand("../scripts/upstream_parity/oracle.js", __DIR__)
                         ) and
                         File.exists?(
                           Path.join(
                             Path.expand("../scripts/upstream_parity", __DIR__),
                             "node_modules"
                           )
                         )

  if @live_oracle_enabled do
    property "credential offer output matches the pinned JS oracle" do
      check all(
              issuer_path <- member_of(["", "/issuer", "/tenant/acme"]),
              include_auth_server <- boolean(),
              include_auth_code <- boolean(),
              include_preauth <- boolean(),
              interval <- integer(0..10),
              max_runs: 20
            ) do
        grants =
          %{}
          |> maybe_put(
            "authorization_code",
            auth_code_grant(
              include_auth_code,
              include_auth_server,
              "https://issuer.delegate.local" <> issuer_path
            )
          )
          |> maybe_put(
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            preauth_grant(
              include_preauth,
              include_auth_server,
              interval,
              "https://issuer.delegate.local" <> issuer_path
            )
          )

        credential_issuer = "https://issuer.delegate.local" <> issuer_path

        input = %{
          "credential_issuer" => credential_issuer,
          "credential_configuration_ids" => ["agent_delegation_jwt"],
          "configurations" => configurations(),
          "authorization_servers" => if(include_auth_server, do: [credential_issuer], else: nil),
          "grants" => grants
        }

        js = oracle!("credential_offer", input)

        opts =
          []
          |> maybe_put_opt(:authorization_code, authorization_code_grant(grants))
          |> maybe_put_opt(:pre_authorized_code, pre_authorized_code_grant(grants))

        elixir =
          ExOpenid4vc.credential_offer(
            credential_issuer,
            ["agent_delegation_jwt"],
            opts
          )

        assert js == elixir
      end
    end

    property "nonce response output matches the pinned JS oracle" do
      check all(
              nonce_suffix <- positive_integer(),
              expires_in <- integer(0..600),
              max_runs: 20
            ) do
        input = %{
          "c_nonce" => "nonce_#{nonce_suffix}",
          "c_nonce_expires_in" => expires_in
        }

        assert oracle!("nonce_response", input) ==
                 ExOpenid4vc.nonce_response(input["c_nonce"], input["c_nonce_expires_in"])
      end
    end

    property "credential response output matches the pinned JS oracle" do
      check all(
              nonce_suffix <- positive_integer(),
              expires_in <- integer(0..600),
              credential_suffix <- positive_integer(),
              max_runs: 20
            ) do
        input = %{
          "format" => "jwt_vc_json",
          "credential" => "eyJhbGciOiJFUzI1NiJ9.payload.#{credential_suffix}",
          "c_nonce" => "nonce_#{nonce_suffix}",
          "c_nonce_expires_in" => expires_in
        }

        assert oracle!("credential_response", input) ==
                 ExOpenid4vc.credential_response(
                   input["format"],
                   input["credential"],
                   c_nonce: input["c_nonce"],
                   c_nonce_expires_in: input["c_nonce_expires_in"]
                 )
      end
    end

    property "deferred pending response output matches the pinned JS oracle" do
      check all(
              tx_suffix <- positive_integer(),
              interval <- integer(1..30),
              max_runs: 20
            ) do
        input = %{
          "transaction_id" => "txn_#{tx_suffix}",
          "interval" => interval
        }

        assert oracle!("deferred_credential_response", input) ==
                 elem(
                   ExOpenid4vc.deferred_credential_response(
                     transaction_id: input["transaction_id"],
                     interval: input["interval"]
                   ),
                   1
                 )
      end
    end

    defp oracle!(operation, input) do
      {output, 0} =
        System.cmd("node", [oracle_script(), operation, Jason.encode!(drop_nils(input))],
          cd: oracle_root()
        )

      case Jason.decode!(output) do
        %{"ok" => true, "result" => result} -> result
        other -> raise "oracle call failed: #{inspect(other)}"
      end
    end

    defp configurations do
      %{
        "agent_delegation_jwt" => %{
          "format" => "jwt_vc_json",
          "scope" => "agent_delegation",
          "cryptographic_binding_methods_supported" => ["did:jwk"],
          "credential_signing_alg_values_supported" => ["ES256"],
          "proof_types_supported" => %{
            "jwt" => %{"proof_signing_alg_values_supported" => ["ES256"]}
          },
          "credential_definition" => %{
            "type" => ["VerifiableCredential", "AgentDelegationCredential"]
          }
        }
      }
    end

    defp auth_code_grant(true, true, authorization_server),
      do: %{"issuer_state" => "issuer_state_123", "authorization_server" => authorization_server}

    defp auth_code_grant(true, false, _authorization_server),
      do: %{"issuer_state" => "issuer_state_123"}

    defp auth_code_grant(false, _include_auth_server, _authorization_server), do: nil

    defp preauth_grant(true, true, interval, authorization_server),
      do: %{
        "pre-authorized_code" => "preauth_123",
        "authorization_server" => authorization_server,
        "interval" => interval
      }

    defp preauth_grant(true, false, interval, _authorization_server),
      do: %{
        "pre-authorized_code" => "preauth_123",
        "interval" => interval
      }

    defp preauth_grant(false, _include_auth_server, _interval, _authorization_server), do: nil

    defp authorization_code_grant(%{"authorization_code" => grant}) when is_map(grant) do
      ExOpenid4vc.authorization_code_grant(
        issuer_state: grant["issuer_state"],
        authorization_server: grant["authorization_server"]
      )
    end

    defp authorization_code_grant(_), do: nil

    defp pre_authorized_code_grant(%{
           "urn:ietf:params:oauth:grant-type:pre-authorized_code" => grant
         })
         when is_map(grant) do
      ExOpenid4vc.pre_authorized_code_grant(grant["pre-authorized_code"],
        authorization_server: grant["authorization_server"],
        interval: grant["interval"]
      )
    end

    defp pre_authorized_code_grant(_), do: nil

    defp maybe_put(map, _key, nil), do: map
    defp maybe_put(map, key, value), do: Map.put(map, key, value)

    defp maybe_put_opt(opts, _key, nil), do: opts
    defp maybe_put_opt(opts, key, value), do: Keyword.put(opts, key, value)

    defp oracle_script, do: Path.expand("../scripts/upstream_parity/oracle.js", __DIR__)
    defp oracle_root, do: Path.expand("../scripts/upstream_parity", __DIR__)

    defp drop_nils(map) do
      Enum.reduce(map, %{}, fn
        {_key, nil}, acc -> acc
        {key, value}, acc -> Map.put(acc, key, value)
      end)
    end
  else
    @tag skip: "set EX_OPENID4VC_LIVE_ORACLE=1 and install scripts/upstream_parity deps to run"
    test "credential offer output matches the pinned JS oracle" do
    end

    @tag skip: "set EX_OPENID4VC_LIVE_ORACLE=1 and install scripts/upstream_parity deps to run"
    test "nonce response output matches the pinned JS oracle" do
    end

    @tag skip: "set EX_OPENID4VC_LIVE_ORACLE=1 and install scripts/upstream_parity deps to run"
    test "credential response output matches the pinned JS oracle" do
    end

    @tag skip: "set EX_OPENID4VC_LIVE_ORACLE=1 and install scripts/upstream_parity deps to run"
    test "deferred pending response output matches the pinned JS oracle" do
    end
  end
end
