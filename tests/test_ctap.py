from fido2.hid import CtapHidDevice, CAPABILITY
from fido2.ctap2 import CTAP2
from binascii import a2b_hex

import unittest

dev = None

def get_device():
    devs = list(CtapHidDevice.list_devices())
    assert len(devs) == 1
    return devs[0]

#https://github.com/Yubico/python-fido2/blob/master/test/test_hid.py
class TestInfo(unittest.TestCase):
    def test_info(self):
        global dev
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

if __name__ == '__main__':
    try:
        dev = get_device()
    except Exception:
        print("Unable to find hid device")

    unittest.main()