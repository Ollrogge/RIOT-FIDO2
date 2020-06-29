from fido2.hid import *

def get_device():
    devs = list(CtapHidDevice.list_devices())
    assert len(devs) == 1
    return devs[0]

def welcome():
    print("CTAP HID shell testing application")
    print("Commands: ")
    print("- ping <msg>")
    print("- wink")
    print("- quit")

def main_loop(dev):
    welcome()
    while True:
        inp = input("> ")
        inp = inp.split(" ")

        command = inp[0]

        if command == "ping":
            if (len(inp) < 2):
                print("Missing ping argument")
            else:
                resp = dev.ping(inp[1].encode())
                print("Resp: ", resp)
        elif command == "wink":
            resp = dev.wink()
        elif command == "quit":
            break
        else:
            print("Unknown command")
            welcome()

if __name__ == '__main__':
    try:
        dev = get_device()
    except Exception:
        self.fail("Unable to find hid device")
        exit(0)

    main_loop(dev)