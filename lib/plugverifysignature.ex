defmodule Jwt.Plugs.VerifySignature do
    import Plug.Conn

    require Logger

    @timeutils Application.get_env(:jwt, :timeutils, Jwt.TimeUtils)
    @authorization_header "authorization"
    @bearer "Bearer "
    @invalid_header_error {:error, "Invalid authorization header value."}
    @expired_token_error {:error, "Expired token."}
    @five_minutes 5 * 60
    @default_options %{:ignore_token_expiration => false, :time_window => @five_minutes}

    def init(opts) do
        case Enum.count(opts) do
          2 -> opts
          _ -> [@default_options.ignore_token_expiration, @default_options.time_window]
        end
    end

    def call(conn, opts) do
        Logger.debug "call. Authorization header: #{inspect get_req_header(conn, @authorization_header)}"

        List.first(get_req_header(conn, @authorization_header))
        |> extract_token
        |> verify_token(opts)
        |> continue_if_verified(conn)
    end

    defp extract_token(auth_header) when is_binary(auth_header) and auth_header != "" do
        case String.starts_with?(auth_header, @bearer) do
          true -> {:ok, List.last(String.split(auth_header, @bearer))}
          false -> 
            Logger.debug "Auth should starts with #{@bearer}, got: #{auth_header}"
            @invalid_header_error
        end
    end
    defp extract_token(header) do
        Logger.debug "Should be is not empty or binary: #{header}"
        @invalid_header_error
    end

    defp verify_token({:ok, token}, opts) do
        verify_signature(token) |> verify_expiration(opts)
    end
    defp verify_token({:error, _}, _opts), do: @invalid_header_error

    defp verify_signature(token), do: Jwt.verify(token)

    defp verify_expiration({:ok, claims}, opts) do
        [ignore_token_expiration, time_window] = opts
        IO.inspect claims["exp"]
        IO.inspect time_window
        IO.inspect claims["exp"] - time_window
        expiration_date = claims["exp"] - time_window
        now = @timeutils.get_system_time()

        cond do
            ignore_token_expiration -> {:ok, claims}
            now > expiration_date -> {:error, "Expired token. now: #{now}, exp: #{claims["exp"] - time_window}"}
            now < expiration_date -> {:ok, claims}
        end
    end
    defp verify_expiration({:error, _}, _opts), do: @invalid_header_error

    defp continue_if_verified({:ok, claims}, conn) do
        assign(conn, :jwtclaims, claims)
    end
    defp continue_if_verified({:error, error}, conn) do
        Logger.debug "verify error: #{error}"
        conn
         |> send_resp(401, "")
         |> halt
    end
end