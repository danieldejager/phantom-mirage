#
# Minimal embedded Python 3 service for honeyd (#36).
#
#   add <template> tcp port 7 internal "echo_banner"
#
# honeyd imports this module once (it must be on sys.path, e.g. via
# PYTHONPATH or the honeyd data directory) and calls the four hooks
# below for every connection. Data from the attacker arrives as bytes;
# honeyd_writedata returns bytes (str is sent as UTF-8) or None to
# close the connection.
#
import honeyd

BANNER = b"honeyd echo (python " + honeyd.version.encode() + b")\r\n"


def honeyd_init(env):
    state = {"out": [BANNER], "env": env}
    honeyd.read_selector(honeyd.EVENT_ON)
    honeyd.write_selector(honeyd.EVENT_ON)
    return state


def honeyd_readdata(state, data):
    if data.strip().lower() == b"quit":
        state["out"].append(None)
    else:
        state["out"].append(b"echo: " + data)
        # read events are one-shot: ask for the next chunk
        honeyd.read_selector(honeyd.EVENT_ON)
    honeyd.write_selector(honeyd.EVENT_ON)
    honeyd.log("python echo %d bytes from %s"
               % (len(data), state["env"]["HONEYD_IP_SRC"]))


def honeyd_writedata(state):
    data = state["out"].pop(0)
    if not state["out"]:
        honeyd.write_selector(honeyd.EVENT_OFF)
    return data


def honeyd_end(state):
    pass
