from fido2.hid import *
from fido2.ctap2 import CTAP2, PinProtocolV1, AttestationObject, AttestedCredentialData, CtapError
from fido2.attestation import Attestation
from fido2.client import Fido2Client
from fido2.server import Fido2Server
from getpass import getpass
from binascii import a2b_hex
from hashlib import sha256
import threading
import time

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

def make_credential(server, client, user, rk= None):
    start = time.time_ns()
    create_options, state = server.register_begin(user, resident_key= rk)

    attestation_object, client_data = client.make_credential(
        create_options["publicKey"])

    auth_data = server.register_complete(state, client_data, attestation_object)
    credential = [auth_data.credential_data]

    end = time.time_ns()
    total_us = (end - start) // 1000

    return credential

def authenticate(server, client, credentials):
    start = time.time_ns()
    request_options, state = server.authenticate_begin(credentials)

    assertions, client_data = client.get_assertion(request_options["publicKey"])

    for assertion in assertions:
        server.authenticate_complete(
            state,
            credentials,
            assertion.credential["id"],
            client_data,
            assertion.auth_data,
            assertion.signature,
        )

    end = time.time_ns()
    total_us = (end - start) // 1000