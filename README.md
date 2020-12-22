# RIOT-FIDO2

This is an implementation of the CTAP2 protocol as module in the IoT operating system RIOT.

It was developed and tested on the [Nordic nRF52840-DK](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-DK).

# Disclaimer

This project is proof-of-concept and a research platform. It is NOT meant for a daily usage. It's still under development and as such comes with limitation. The limitations are:

1. USB only
2. Only self attestation
3. No Extension support
4. No FIDO1 backward compatibility
5. No CTAP2.1 support

# Installation

1. Clone this repository + submodules:
    ```bash
    git clone --recurse-submodules https://github.com/Ollrogge/RIOT-FIDO2
    ```

2. Before building this application please check the [Getting started](https://doc.riot-os.org/getting-started.html) guide of RIOT and install the required toolchain, in order to be able to build RIOT.

3. Once all tools are installed. Build the binary and flash the device:
    ```bash
    make flash
    ```

# Try it out

To try out the FIDO2 authentication process, visit a FIDO2 test website such as: [WebAuthn.io](https://webauthn.io/). There you can try out the registration and authentication process using this implementation.

The default settings on the site should work. Just choose a username and click register.

Please use the Google Chrome or Chromium browser. Other browser currently do not support CBOR messages.

# Tests

For testing, check the README of the [fido2-tests](https://github.com/Ollrogge/fido2-tests) repository.
