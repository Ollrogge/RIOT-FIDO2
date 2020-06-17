from fido2.hid import CtapHidDevice
import unittest

dev = None

def get_device():
    devs = list(CtapHidDevice.list_devices())
    assert len(devs) == 1
    return devs[0]

#https://github.com/Yubico/python-fido2/blob/master/test/test_hid.py
class TestPing(unittest.TestCase):
    def test_ping(self):
        global dev

        msg1 = b"Hello world!"
        msg2 = b"Test     iing this   !"
        msg3 = b"               "
        msg4 = b""

        self.assertEqual(dev.ping(msg1).rstrip(b'\x00'), msg1)
        self.assertEqual(dev.ping(msg2).rstrip(b'\x00'), msg2)
        self.assertEqual(dev.ping(msg3).rstrip(b'\x00'), msg3)
        self.assertEqual(dev.ping(msg4).rstrip(b'\x00'), msg4)

        dev.close()

if __name__ == '__main__':
    try:
        dev = get_device()
    except Exception:
        print("Unable to find hid device")

    unittest.main()