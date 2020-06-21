from fido2.hid import *
import unittest
import signal

def get_device():
    devs = list(CtapHidDevice.list_devices())
    assert len(devs) == 1
    return devs[0]

def send_init_packet(dev, cid, cmd, payload_size=0, payload=b""):
    _dev = dev._dev
    _dev.cid = cid
    packet = hidtransport.UsbHidTransport.InitPacket(_dev.packet_size, _dev.cid, cmd,
             payload_size, payload)

    _dev.InternalSendPacket(packet)
    status, resp = _dev.InternalRecv()
    status ^= TYPE_INIT
    if status == CTAPHID.ERROR:
        raise CtapError(resp[0])

def send_cont_packet(dev, cid, seq=0, payload=b""):
    _dev = dev._dev
    _dev.cid = cid
    packet = hidtransport.UsbHidTransport.ContPacket(_dev.packet_size, _dev.cid, seq, payload)
    _dev.InternalSendPacket(packet)
    status, resp = _dev.InternalRecv()

class test_timeout:
  def __init__(self, seconds, error_message=None):
    if error_message is None:
      error_message = 'test timed out after {}s.'.format(seconds)
    self.seconds = seconds
    self.error_message = error_message

  def handle_timeout(self, signum, frame):
    raise TimeoutError(self.error_message)

  def __enter__(self):
    signal.signal(signal.SIGALRM, self.handle_timeout)
    signal.alarm(self.seconds)

  def __exit__(self, exc_type, exc_val, exc_tb):
    signal.alarm(0)

class TimeoutError(Exception):
    pass

#https://github.com/Yubico/python-fido2/blob/master/test/test_hid.py
class TestPing(unittest.TestCase):
    def test_ping(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        msg1 = b"Hello world!"
        msg2 = b"Test     iing this   !"
        msg3 = b"               "
        msg4 = b""

        self.assertEqual(dev.ping(msg1).rstrip(b'\x00'), msg1)
        self.assertEqual(dev.ping(msg2).rstrip(b'\x00'), msg2)
        self.assertEqual(dev.ping(msg3).rstrip(b'\x00'), msg3)
        self.assertEqual(dev.ping(msg4).rstrip(b'\x00'), msg4)

        dev.close()

class TestErrors(unittest.TestCase):
    def test_wrong_cid_for_command(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        cmd = (TYPE_INIT | CTAPHID.WINK)
        cid = hidtransport.UsbHidTransport.U2FHID_BROADCAST_CID

        try:
            send_init_packet(dev, cid, cmd)
            self.fail("broadcast cid for anything else than INIT command should cause an error")
        except CtapError as e:
            self.assertEqual(e.code, CtapError.ERR.INVALID_CHANNEL)

        cid = bytearray([0x00]*4)

        try:
            send_init_packet(dev, cid, cmd)
            self.fail("cid = 0 cid should always cause an error")
        except CtapError as e:
            self.assertEqual(e.code, CtapError.ERR.INVALID_CHANNEL)

        cmd = (TYPE_INIT | CTAPHID.INIT)

        try:
            send_init_packet(dev, cid, cmd)
            self.fail("cid = 0 cid should always cause an error")
        except CtapError as e:
            self.assertEqual(e.code, CtapError.ERR.INVALID_CHANNEL)

        dev.close()

    def test_cont_pkt_before_init(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        cid = hidtransport.UsbHidTransport.U2FHID_BROADCAST_CID

        with test_timeout(1):
            try:
                send_cont_packet(dev, cid)
            except TimeoutError as e:
                return
        return

        self.fail("cont pkt before init should be ignored and therefore cause a timeout error")

        dev.close()

if __name__ == '__main__':
    unittest.main()