defmodule Jwt do
    import Plug.Conn

    require Logger

    @google_certs_api Application.get_env(:jwt, :googlecerts, Jwt.GoogleCerts.PublicKey)
    @firebase_certs_api Application.get_env(:jwt, :firebasecerts, Jwt.FirebaseCerts.PublicKey)
    @invalid_token_error {:error, "Invalid token"}
    @invalid_signature_error {:error, "Invalid signature"}
    @check_signature Application.get_env(:jwt, :check_signature, true)
    @key_id "kid"
    @alg "alg"

    @doc """
        Verifies a Google or Firebase generated JWT token against the current public certificates and returns the claims
        if the token's signature is verified successfully.

        ## Example
        {:ok, {claims}} = Jwt.verify token
    """
    def verify(token) do
        token_parts = String.split token, "."
        Logger.debug "Check signature: #{@check_signature}"
        _verify(Enum.map(token_parts, fn(part) -> Base.url_decode64(part, padding: false) end), token_parts, @check_signature)
    end

    defp _verify([_, {:ok, claims}, _], [header_b64, claims_b64, _signature_b64], false) do

        {:ok, Poison.decode! claims} |> IO.inspect
    end

    defp _verify([{:ok, header}, {:ok, _claims}, {:ok, signature}], [header_b64, claims_b64, _signature_b64], true) do
        header
            |> extract_key_id
            |> retrieve_cert_exp_and_mod_for_key
            |> verify_signature(header_b64, claims_b64, signature)
    end

    defp _verify(parts, parts64, _) do 
        Logger.debug "Error take parts of token. Parts: #{inspect parts}. Parts64: #{inspect parts64}"
        @invalid_token_error
    end

    defp extract_key_id(header), do: Poison.Parser.parse!(header)[@key_id]

    defp retrieve_cert_exp_and_mod_for_key(key_id) do
        @google_certs_api.getfor(key_id) 
            |> case do
                {:ok, cert_data} -> {:ok, cert_data}
                {:notfounderror, _} -> @firebase_certs_api.getfor(key_id)
                _ -> 
                    Logger.debug "Cert not found"
                    @invalid_token_error 
            end
    end

    defp verify_signature({:ok, %{exp: exponent, mod: modulus}}, header_b64, claims_b64, signature) do
        msg = header_b64 <> "." <> claims_b64

        case :crypto.verify :rsa, :sha256, msg, signature, [exponent, modulus] do
            true -> {:ok, Poison.Parser.parse! Base.url_decode64!(claims_b64, padding: false)}
            false -> @invalid_signature_error
        end
    end

    defp verify_signature({:error, message}, _, _, _) do
        Logger.debug "Verify error: #{message}"
        @invalid_token_error
    end
    defp verify_signature(_, _, _, _), do: @invalid_signature_error
end
