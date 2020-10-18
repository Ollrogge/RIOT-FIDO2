from utils import *
import sys

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
    devs = list(CtapHidDevice.list_devices())

    assert len(sys.argv) == 2
    assert len(devs) == 1

    dev = devs[0]
    runs = int(sys.argv[1], 10)

    ctap = CTAP2(dev)

    # reset state
    ctap.reset()

    runtimes, creds = benchmark_make_credential(dev, runs, rk = True)
    runtimes = "".join([f"{t}\n" for t in runtimes])
    with open("./bechmark_mc_RIOT.txt", 'w+') as f:
        f.write(runtimes)

    runtimes = benchmark_get_assertion(dev, runs, creds)
    runtimes = "".join([f"{t}\n" for t in runtimes])
    with open("./bechmark_ga_RIOT.txt", 'w+') as f:
        f.write(runtimes)