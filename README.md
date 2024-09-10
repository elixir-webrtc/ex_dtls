# ExDTLS

[![Hex.pm](https://img.shields.io/hexpm/v/ex_dtls.svg)](https://hex.pm/packages/ex_dtls)
[![API Docs](https://img.shields.io/badge/api-docs-yellow.svg?style=flat)](https://hexdocs.pm/ex_dtls/)
[![CI](https://img.shields.io/github/actions/workflow/status/elixir-webrtc/ex_dtls/ci.yml?logo=github&label=CI)](https://github.com/elixir-webrtc/ex_dtls/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/elixir-webrtc/ex_dtls/graph/badge.svg?token=E98NHC8B00)](https://codecov.io/gh/elixir-webrtc/ex_dtls)

DTLS and DTLS-SRTP library for Elixir, based on [OpenSSL].

`ExDTLS` allows a user to perform DTLS handshake (including DTLS-SRTP one)
without requiring any socket.
Instead, it generates DTLS packets that a user has to transport to the peer.
Thanks to this DTLS handshake can be performed on the third-party socket e.g. one used to
establish a connection via ICE protocol.

Starting from v0.16.0, `ExDTLS` can also be used to send arbitrary data using DTLS datagrams, see `ExDTLS.write_data/2`.

## Installation

The package can be installed by adding `ex_dtls` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_dtls, "~> 0.16.0"}
  ]
end
```

## Usage

`ExDTLS` uses OpenSSL under the hood.
Make sure you have it installed on your OS.

Init `ExDTLS` on both peers with:

```elixir
# One peer should be a client (use `mode: :client`) and the other
# one a server (use `mode: :server`).
# DTLS-SRTP is the most common use case for ExDTLS, we'll enable it.
dtls = ExDTLS.init(mode: :client, dtls_srtp: true)
```

On a peer running in a client mode start performing DTLS handshake

```elixir
{packets, timeout} = ExDTLS.do_handshake(dtls)
```

You will obtain initial handshake packets and a `timeout`.
`packets` has to be passed to the second peer (using your own socket UDP).
`timeout` is a time after which `ExDTLS.handle_timeout/1` should be called.

After receiving initial DTLS packets on the second peer pass them to `ExDTLS`:

```elixir
{:handshake_packets, packets, timeout} = ExDTLS.handle_data(dtls, packets)
```

As a result, we will also get some new packets that have to be passed to the first peer.

After some back and forth DTLS handshake should be finished successfully.
The peer that finishes the handshake first will return `{:handshake_finished, local_keying_material, remote_keying_material, protection_profile, packets}` tuple.
These packets have to be sent to the second peer, so it can finish its handshake too and
return `{:handshake_finished, local_keying_material, remote_keying_material, protection_profile}` tuple.

For more complete examples please refer to [ex_webrtc] where we use `ex_dtls`
or to our integration tests.

## Debugging

Add `compiler_flags: ["-DEXDTLS_DEBUG"],` in `bundlex.exs` to
get debug logs from the native code.

## Copyright and License

Copyright 2020, [Software Mansion](https://swmansion.com/?utm_source=git&utm_medium=readme&utm_campaign=ex_dtls)

[![Software Mansion](https://logo.swmansion.com/logo?color=white&variant=desktop&width=200&tag=membrane-github)](https://swmansion.com/?utm_source=git&utm_medium=readme&utm_campaign=ex_dtls)

Licensed under the [Apache License, Version 2.0](LICENSE)

[OpenSSL]: https://www.openssl.org/
[ex_webrtc]: https://github.com/elixir-webrtc/ex_webrtc
