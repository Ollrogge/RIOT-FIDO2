from fido2.hid import *
from fido2.ctap2 import CTAP2, PinProtocolV1, AttestationObject, AttestedCredentialData, CtapError
from fido2.attestation import Attestation
from fido2.client import Fido2Client
from fido2.server import Fido2Server
from getpass import getpass
from binascii import a2b_hex
from hashlib import sha256
import threading
from time import sleep

import unittest

dev = None

def send_init_packet(dev, cmd, payload_size=0, payload=b""):
    _dev = dev._dev
    max_payload = _dev.packet_size - 7
    frame = payload[:max_payload]
    packet = hidtransport.UsbHidTransport.InitPacket(_dev.packet_size, _dev.cid, cmd,
             payload_size, frame)

    _dev.InternalSendPacket(packet)
    status, resp = _dev.InternalRecv()
    status ^= TYPE_INIT
    if status == CTAPHID.ERROR:
        raise CtapError(resp[0])

def get_device():
    devs = list(CtapHidDevice.list_devices())
    assert len(devs) == 1
    return devs[0]

#https://github.com/Yubico/python-fido2/blob/master/test/test_hid.py
class TestCtap(unittest.TestCase):
    @unittest.skip
    def test_info(self):
        print()
        print("*** test_info ***")
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        if dev.capabilities & CAPABILITY.CBOR:
            ctap2 = CTAP2(dev)
            info = ctap2.get_info()

            print("Info: ", info)
            print("")

            self.assertEqual(info.versions, ['FIDO_2_0'])
            self.assertEqual(info.aaguid, a2b_hex("9c295865fa2c36b705a42320af9c8f16"))

        else:
            print("Device does not support CBOR")

        dev.close()

    @unittest.skip
    #todo: use this test only with user presence test, else it will probably fail quite often
    def test_cancel(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        def send_cancel(dev):
            sleep(0.25)
            cmd = (TYPE_INIT | CTAPHID.CANCEL)
            send_init_packet(dev, cmd)
            print("1")

        ctap = CTAP2(dev)
        pin = PinProtocolV1(ctap)
        PIN ="12345"

        # reset state so we can set pin without error
        ctap.reset()
        t = threading.Thread(target=send_cancel, args=(dev,))
        t.start()
        try:
            pin.set_pin(PIN)
            print("2")
        except CtapError as e:
            self.assertEqual(e.code, CtapError.ERR.KEEPALIVE_CANCEL)

    @unittest.skip
    def test_pin(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        if dev.capabilities & CAPABILITY.CBOR:
            ctap = CTAP2(dev)
            pin1 = PinProtocolV1(ctap)
            PIN = "12345"
            PIN2 = "54321"
            PIN_FALSE = "11111"

            # reset state so we can set pin without error
            ctap.reset()

            pin1.set_pin(PIN)

            retries_max = pin1.get_pin_retries()

            try:
                resp = pin1.get_pin_token(PIN_FALSE)
            except CtapError as e:
                self.assertEqual(e.code, CtapError.ERR.PIN_INVALID)

            retries_left = pin1.get_pin_retries()
            self.assertEqual(retries_max - 1, retries_left)

            resp = pin1.get_pin_token(PIN)
            print(f"Get pin token resp: {resp}")

            retries_left = pin1.get_pin_retries()
            self.assertEqual(retries_max, retries_left)

            pin1.change_pin(PIN, PIN2)

            try:
                resp = pin1.get_pin_token(PIN)
            except CtapError as e:
                self.assertEqual(e.code, CtapError.ERR.PIN_INVALID)

            resp = pin1.get_pin_token(PIN2)

            for i in range(3):
                try:
                    resp = pin1.get_pin_token(PIN)
                except CtapError as e:
                    if i == 2:
                        self.assertEqual(e.code, CtapError.ERR.PIN_AUTH_BLOCKED)
                    else:
                        self.assertEqual(e.code, CtapError.ERR.PIN_INVALID)

        else:
            print("Device does not support CBOR")

    #@unittest.skip
    def test_make_credential_and_get_assertion(self):
        print()
        print("*** test_make_credential_and_get_assertion ***")
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        ctap = CTAP2(dev)
        pin1 = PinProtocolV1(ctap)

        # reset state so we can set pin without error
        ctap.reset()

        client = Fido2Client(dev, "https://example.com")

        server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")
        user = {"id": b"user_id", "name": "A. User"}

         # Prepare parameters for makeCredential
        create_options, state = server.register_begin(user)

        attestation_object, client_data = client.make_credential(
            create_options["publicKey"])

        # Complete registration
        auth_data = server.register_complete(state, client_data, attestation_object)
        credentials = [auth_data.credential_data]

        print("New credential created!")

        # Prepare parameters for getAssertion
        request_options, state = server.authenticate_begin(credentials)

        assertions, client_data = client.get_assertion(request_options["publicKey"])
        assertion = assertions[0]  # Only one cred in allowCredentials, only one response.

        # Complete authenticator
        server.authenticate_complete(
            state,
            credentials,
            assertion.credential["id"],
            client_data,
            assertion.auth_data,
            assertion.signature,
        )

        print("Credential authenticated!")


    @unittest.skip
    def test_make_credential_and_get_assertion_PIN(self):
        print()
        print("*** test_make_credential_and_get_assertion with PIN***")
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        uv = "preferred"
        PIN = "12345"

        ctap = CTAP2(dev)
        pin1 = PinProtocolV1(ctap)

        # reset state so we can set pin without error
        ctap.reset()

        pin1.set_pin(PIN)

        client = Fido2Client(dev, "https://example.com")

        #PIN has been set
        self.assertTrue(client.info.options.get("clientPin"))

        server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")
        user = {"id": b"user_id", "name": "A. User"}

        # Prepare parameters for makeCredential
        create_options, state = server.register_begin(user, user_verification=uv)

        attestation_object, client_data = client.make_credential(
            create_options["publicKey"], pin=PIN)

        # Complete registration
        auth_data = server.register_complete(state, client_data, attestation_object)
        credentials = [auth_data.credential_data]

        print("New credential created!")

        # Prepare parameters for getAssertion
        request_options, state = server.authenticate_begin(credentials, user_verification=uv)

        assertions, client_data = client.get_assertion(request_options["publicKey"], pin=PIN)
        assertion = assertions[0]  # Only one cred in allowCredentials, only one response.

        # Complete authenticator
        server.authenticate_complete(
            state,
            credentials,
            assertion.credential["id"],
            client_data,
            assertion.auth_data,
            assertion.signature,
        )

        print("Credential authenticated!")

if __name__ == '__main__':
    unittest.main()
