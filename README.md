# Lumen
A private Lumina server that can be used with IDA Pro 7.2+.

[lumen.abda.nl](https://lumen.abda.nl/) runs this server.

You can read about the protocol research [here](https://abda.nl/posts/introducing-lumen/).

## Features
- Stores function signatures so you (and your team) can quickly identify functions that you found in the past using IDA's built-in Lumina features.
- Backed by PostgreSQL
- Experimental HTTP API that allows querying the database for comments by file or function hash.

## Getting Started
### Running the server
Pre-built binaries are not distributed at the moment, you will have to build _lumen_ on your own. 

1. `git clone https://github.com/naim94a/lumen.git`
2. Get a rust toolchain: https://rustup.rs/
3. `cd lumen`
4. Setup a Postgres database and execute src/schema.sql on it
5. `cargo +nightly build --release`

### Usage
```
./lumen -c config.toml
```

### Configuring IDA
You will need IDA Pro 7.2 or above in order to use _lumen_.

> The following information may get sent to _lumen_ server: IDA key, Hostname, IDB path, original file path, file MD5, function signature, stack frames & comments.

- In your IDA's installation directory open "cfg\ida.cfg" with your favorite text editor _(Example: C:\Program Files\IDA Pro 7.5\cfg\ida.cfg)_
- Locate the commented out `LUMINA_HOST`, `LUMINA_PORT`, and change their values to the address of your _lumen_ server.
- If you didn't configure TLS, Add "LUMINA_TLS = NO" after the line with `LUMINA_PORT`.

Example:
```C
LUMINA_HOST = "192.168.1.1";
LUMINA_PORT = 1234

// Only if TLS isn't used:
LUMINA_TLS = NO
```

### Configuring TLS
IDA Pro uses a pinned certificate for Lumina's communcation, so adding a self-signed certificate to your root certificates won't work.
Luckily, we can override the hard-coded public key by writing a DER-base64 encoded certificate to "hexrays.crt" in IDA's install directory.

You may find the following commands useful:
```bash
# create a certificate
openssl req -x509 -newkey rsa:4096 -keyout lumen_key.pem -out lumen_crt.pem -days 365 -nodes

# convert to pkcs12 for lumen; used for `lumen.tls` in config
openssl pkcs12 -export -out lumen.p12 -inkey lumen_key.pem -in lumen_crt.pem

# export public-key for IDA; Copy hexrays.crt to IDA installation folder
openssl x509 -in lumen_crt.pem -out hexrays.crt
```

No attempt is made to merge function data - this may casuse a situation where metadata is inconsistent.
Instead, the metadata with the highest calculated score is returned to the user.


---

Developed by [Naim A.](https://github.com/naim94a); License: MIT.
