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
    max_payload = _dev.packet_size - 7
    frame = payload[:max_payload]
    packet = hidtransport.UsbHidTransport.InitPacket(_dev.packet_size, _dev.cid, cmd,
             payload_size, frame)

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
#@unittest.skip
class TestPing(unittest.TestCase):
    def test_ping(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        _dev = dev._dev
        max_payload = _dev.packet_size - 7

        msg1 = b"Hello world!"
        msg2 = b"Test     iing this   !"
        msg3 = b"               "
        msg4 = b""
        msg5 = b"A"*427

        self.assertEqual(dev.ping(msg1).rstrip(b'\x00'), msg1)
        self.assertEqual(dev.ping(msg2).rstrip(b'\x00'), msg2)
        self.assertEqual(dev.ping(msg3).rstrip(b'\x00'), msg3)
        self.assertEqual(dev.ping(msg4).rstrip(b'\x00'), msg4)
        self.assertEqual(dev.ping(msg5).rstrip(b'\x00'), msg5)

        dev.close()

class TestErrors(unittest.TestCase):
    #@unittest.skip
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

    #@unittest.skip
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

        self.fail("cont pkt before init should be ignored and therefore cause a timeout error")

        dev.close()

    #@unittest.skip
    def test_cont_pkt_timeout(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        payload = b"A"*128
        _dev = dev._dev
        cid = _dev.cid
        max_payload = _dev.packet_size - 7
        frame = payload[:max_payload]

        cmd = (TYPE_INIT | CTAPHID.PING)

        packet = hidtransport.UsbHidTransport.InitPacket(_dev.packet_size, _dev.cid, cmd,
                                                        len(payload), frame)

        _dev.InternalSendPacket(packet)

        with test_timeout(2):
            try:
                status, resp = _dev.InternalRecv()
                status ^= TYPE_INIT
                self.assertEqual(status, CTAPHID.ERROR)
                self.assertEqual(resp[0], CtapError.ERR.TIMEOUT)
            except TimeoutError as e:
                self.fail("device should send timeout error after roughly 1 second")


    '''
    send WINK command which will block for a little due to wink animation
    immediately send another wink to trigger channel busy error
    '''
    #@unittest.skip
    def test_busy(self):
        try:
            dev = get_device()
        except Exception:
            self.fail("Unable to find hid device")
            return

        _dev = dev._dev
        cmd = (TYPE_INIT | CTAPHID.WINK)
        cid_temp = None

        payload = b""

        packet = hidtransport.UsbHidTransport.InitPacket(_dev.packet_size, _dev.cid, cmd,
                                                        len(payload), payload)

        _dev.InternalSendPacket(packet)

        cid_temp = _dev.cid
        _dev.cid = hidtransport.UsbHidTransport.U2FHID_BROADCAST_CID
        packet = hidtransport.UsbHidTransport.InitPacket(_dev.packet_size, _dev.cid, cmd,
                                                        len(payload), payload)

        _dev.InternalSendPacket(packet)

        status, resp = _dev.InternalRecv()
        status ^= TYPE_INIT

        _dev.cid = cid_temp

        self.assertEqual(status, CTAPHID.ERROR)
        self.assertEqual(resp[0], CtapError.ERR.CHANNEL_BUSY)

        status, resp = _dev.InternalRecv()

        dev.close()

if __name__ == '__main__':
    unittest.main()