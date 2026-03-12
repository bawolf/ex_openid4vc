defmodule ExOpenid4vc.UpstreamParityTest do
  use ExUnit.Case, async: true

  @fixtures_root Path.expand("fixtures/upstream/released", __DIR__)

  test "released upstream parity corpus matches current outputs" do
    manifest = load_json(Path.join(@fixtures_root, "manifest.json"))

    for test_case <- manifest["cases"] do
      recorded = load_json(Path.join([@fixtures_root, "cases", test_case["file"]]))

      assert recorded["oracle"]["ok"],
             "oracle fixture #{test_case["id"]} was recorded as a failure"

      actual = run_operation(recorded["operation"], recorded["input"])

      assert actual == recorded["oracle"]["result"],
             inspect(
               %{
                 case: test_case["id"],
                 expected: recorded["oracle"]["result"],
                 actual: actual
               },
               pretty: true
             )
    end
  end

  defp run_operation("credential_offer", input) do
    opts =
      []
      |> maybe_put_opt(:authorization_code, authorization_code_grant(input))
      |> maybe_put_opt(:pre_authorized_code, pre_authorized_code_grant(input))

    ExOpenid4vc.credential_offer(
      input["credential_issuer"],
      input["credential_configuration_ids"],
      opts
    )
  end

  defp run_operation("nonce_response", input) do
    ExOpenid4vc.nonce_response(input["c_nonce"], input["c_nonce_expires_in"])
  end

  defp run_operation("credential_response", input) do
    ExOpenid4vc.credential_response(
      input["format"],
      input["credential"],
      c_nonce: input["c_nonce"],
      c_nonce_expires_in: input["c_nonce_expires_in"]
    )
  end

  defp run_operation("parse_credential_request", input) do
    {:ok, result} =
      ExOpenid4vc.parse_credential_request(
        input["credential_request"],
        allowed_formats: ["jwt_vc_json"],
        credential_configuration_ids: Map.keys(input["configurations"] || %{}),
        credential_configurations: input["configurations"] || %{}
      )

    result
  end

  defp run_operation("deferred_credential_response", input) do
    {:ok, result} =
      ExOpenid4vc.deferred_credential_response(
        []
        |> maybe_put_opt(:credentials, input["credentials"])
        |> maybe_put_opt(:transaction_id, input["transaction_id"])
        |> maybe_put_opt(:interval, input["interval"])
        |> maybe_put_opt(:notification_id, input["notification_id"])
      )

    result
  end

  defp run_operation("parse_deferred_credential_request", input) do
    {:ok, result} =
      ExOpenid4vc.parse_deferred_credential_request(input["deferred_credential_request"])

    result
  end

  defp authorization_code_grant(%{"grants" => %{"authorization_code" => grant}})
       when is_map(grant) do
    ExOpenid4vc.authorization_code_grant(
      issuer_state: grant["issuer_state"],
      authorization_server: grant["authorization_server"]
    )
  end

  defp authorization_code_grant(_), do: nil

  defp pre_authorized_code_grant(%{
         "grants" => %{
           "urn:ietf:params:oauth:grant-type:pre-authorized_code" => grant
         }
       })
       when is_map(grant) do
    ExOpenid4vc.pre_authorized_code_grant(grant["pre-authorized_code"],
      authorization_server: grant["authorization_server"],
      interval: grant["interval"],
      tx_code: grant["tx_code"]
    )
  end

  defp pre_authorized_code_grant(_), do: nil

  defp maybe_put_opt(opts, _key, nil), do: opts
  defp maybe_put_opt(opts, key, value), do: Keyword.put(opts, key, value)

  defp load_json(path) do
    path
    |> File.read!()
    |> Jason.decode!()
  end
end
