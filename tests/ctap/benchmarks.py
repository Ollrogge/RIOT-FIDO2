from utils import *
import sys
from udp_binding import force_udp_backend


def benchmark_mc_ga(dev, runs, rk = False):
    runtimes_mc = []
    runtimes_ga = []

    client = Fido2Client(dev, "https://example.com")

    server = Fido2Server({"id": "example.com", "name": "Example RP"},
                            attestation="direct")

    for i in range(runs):
        user = {"id": f"user{i}".encode(), "name": "A. User"}

        start = time.time_ns()
        cred = make_credential(server, client, user, rk=rk)
        end = time.time_ns()
        total_us = (end - start) // 1000
        runtimes_mc.append(total_us)

        start = time.time_ns()
        authenticate(server, client, cred)
        end = time.time_ns()
        total_us = (end - start) // 1000
        runtimes_ga.append(total_us)


    return runtimes_mc, runtimes_ga


def benchmark_make_credential(dev, runs, rk = False):
    runtimes = []
    creds = []

    client = Fido2Client(dev, "https://example.com")

    server = Fido2Server({"id": "example.com", "name": "Example RP"},
                            attestation="direct")

    try:
        for i in range(runs):
            user = {"id": f"user{i}".encode(), "name": "A. User"}

            start = time.time_ns()
            cred = make_credential(server, client, user, rk=rk)
            creds.append(cred)
            end = time.time_ns()
            total_us = (end - start) // 1000

            runtimes.append(total_us)
    except Exception as e:
        print(e)
        pass
    finally:
        return runtimes, creds

def benchmark_get_assertion(dev, runs, creds):
    runtimes = []

    client = Fido2Client(dev, "https://example.com")

    server = Fido2Server({"id": "example.com", "name": "Example RP"},
                            attestation="direct")

    try:
        for i in range(runs):
            start = time.time_ns()
            authenticate(server, client, creds[i])
            end = time.time_ns()
            total_us = (end - start) // 1000

            runtimes.append(total_us)
    except Exception as e:
        print(e)
        pass
    finally:
        return runtimes

if __name__ == '__main__':
    assert len(sys.argv) >= 2

    if len(sys.argv) == 3 and sys.argv[2] == 'UDP':
        print("using UDP")
        force_udp_backend()

    devs = list(CtapHidDevice.list_devices())
    assert len(devs) == 1

    dev = devs[0]
    runs = int(sys.argv[1], 10)

    ctap = CTAP2(dev)

    # reset state
    ctap.reset()

    runtimes_mc, runtimes_ga = benchmark_mc_ga(dev, runs)

    runtimes_mc = "".join([f"{t}\n" for t in runtimes_mc])
    with open("/home/h0ps/Uni/BachelorArbeit/Benchmarks/bechmark_mc_rk_RIOT.txt", 'w+') as f:
        f.write(runtimes_mc)

    runtimes_ga = "".join([f"{t}\n" for t in runtimes_ga])
    with open("/home/h0ps/Uni/BachelorArbeit/Benchmarks/bechmark_ga_rk_RIOT.txt", 'w+') as f:
        f.write(runtimes_ga)
