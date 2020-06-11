from fido2.hid import CtapHidDevice
import unittest

#https://github.com/Yubico/python-fido2/blob/master/test/test_hid.py
class HidTest(unittest.TestCase):
    def get_device(self):
        try:
            devs = list(CtapHidDevice.list_devices())
            assert len(devs) == 1
            return devs[0]
        except Exception:
            self.skipTest("Tests require a single FIDO HID device")

    def test_ping(self):
        msg1 = b"Hello world!"
        msg2 = b"Test     iing this   !"
        msg3 = b"               "
        msg4 = b""

        dev = self.get_device()

        self.assertEqual(dev.ping(msg1).rstrip(b'\x00'), msg1)
        self.assertEqual(dev.ping(msg2).rstrip(b'\x00'), msg2)
        self.assertEqual(dev.ping(msg3).rstrip(b'\x00'), msg3)
        self.assertEqual(dev.ping(msg4).rstrip(b'\x00'), msg4)

if __name__ == '__main__':
    unittest.main()