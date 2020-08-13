from fido2.hid import CtapHidDevice, CAPABILITY
from fido2.ctap2 import CTAP2, PinProtocolV1, AttestationObject, AttestedCredentialData
from fido2.attestation import Attestation
from fido2.client import Fido2Client
from fido2.server import Fido2Server
from getpass import getpass
from binascii import a2b_hex
from hashlib import sha256

#from fastecdsa.curve import P256
#from fastecdsa.encoding.der import DEREncoder
#from fastecdsa import keys, ecdsa

import unittest

dev = None

RP_ID = "example.com"

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

            self.assertEqual(info.options, {
                'rk': True,
                'up': True,
                'plat': False
            })
            self.assertEqual(info.max_msg_size, 1024)
        else:
            print("Device does not support CBOR")

        dev.close()

    def test_pin(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        if dev.capabilities & CAPABILITY.CBOR:
            ctap = CTAP2(dev)
            pin1 = PinProtocolV1(ctap)

            resp = pin1.set_pin('12345')
        else:
            print("Device does not support CBOR")

    @unittest.skip
    def test_make_credential_and_get_assertion2(self):
        print()
        print("*** test_make_credential_and_get_assertion ***")
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        use_prompt = False
        pin = None
        uv = "discouraged"

        client = Fido2Client(dev, "https://example.com")
            # Prefer UV if supported
        if client.info.options.get("uv"):
            uv = "preferred"
            print("Authenticator supports User Verification")
        elif client.info.options.get("clientPin"):
            # Prompt for PIN if needed
            pin = getpass("Please enter PIN: ")
        else:
            print("PIN not set, won't use")

        server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")
        user = {"id": b"user_id", "name": "A. User"}

        # Prepare parameters for makeCredential
        create_options, state = server.register_begin(user, user_verification=uv)

        attestation_object, client_data = client.make_credential(
            create_options["publicKey"], pin=pin)

        # Complete registration
        auth_data = server.register_complete(state, client_data, attestation_object)
        credentials = [auth_data.credential_data]

        print("New credential created!")

        print("CLIENT DATA:", client_data)
        print("ATTESTATION OBJECT:", attestation_object)
        print()
        print("CREDENTIAL DATA:", auth_data.credential_data)

        # Prepare parameters for getAssertion
        request_options, state = server.authenticate_begin(credentials, user_verification=uv)

        assertions, client_data = client.get_assertion(request_options["publicKey"], pin=pin)
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

        print("CLIENT DATA:", client_data)
        print()
        print("ASSERTION DATA:", assertion)

'''
    @unittest.skip
    def test_make_credential_and_get_assertion(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        #random hash for now
        m = sha256()
        m.update(b"random stuff")
        client_data_hash = m.digest()
        rp = {"id": RP_ID, "name": "Example RP"}
        user = {"id": b"user_id", "name": "A. User"}
        key_params = [{"type": "public-key", "alg": -7}]

        ctap2 = CTAP2(dev)

        resp = ctap2.make_credential(client_data_hash, rp, user, key_params)

        print("Make credential resp: ", resp)

        sig = resp.att_statement['sig']
        pub_key = resp.auth_data.credential_data.public_key

        Attestation.for_type(resp.fmt)().verify(
            resp.att_statement,
            resp.auth_data,
            client_data_hash
        )

        print("")

        resp = ctap2.get_assertion(RP_ID, client_data_hash)

        print("Get assertion resp: ", resp)

        resp.verify(client_data_hash, pub_key)

        dev.close()
'''

if __name__ == '__main__':
    unittest.main()
