from fido2.hid import CtapHidDevice, CAPABILITY
from fido2.ctap2 import CTAP2
from fido2.client import Fido2Client
from fido2.server import Fido2Server
from binascii import a2b_hex
from hashlib import sha256

import unittest

dev = None

def get_device():
    devs = list(CtapHidDevice.list_devices())
    assert len(devs) == 1
    return devs[0]

#https://github.com/Yubico/python-fido2/blob/master/test/test_hid.py
class TestInfo(unittest.TestCase):
    @unittest.skip
    def test_info(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        if dev.capabilities & CAPABILITY.CBOR:
            ctap2 = CTAP2(dev)
            info = ctap2.get_info()

            self.assertEqual(info.versions, ['FIDO_2_0'])
            self.assertEqual(info.aaguid, a2b_hex("00000000000000000000000000000000"))
            self.assertEqual(info.options, {
                'rk': True,
                'up': False,
                'plat': False
            })
            self.assertEqual(info.max_msg_size, 1024)
        else:
            print("Device does not support CBOR")

        dev.close()

    #@unittest.skip
    def test_make_credential(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        #random hash for now
        m = sha256()
        m.update(b"random stuff")
        client_data_hash = m.digest()
        rp = {"id": "example.com", "name": "Example RP"}
        user = {"id": b"user_id", "name": "A. User"}
        key_params = [{"type": "public-key", "alg": -7}]

        ctap2 = CTAP2(dev)

        resp = ctap2.make_credential(client_data_hash, rp, user, key_params)

        print("RESP: ", resp)

        dev.close()

if __name__ == '__main__':
    unittest.main()