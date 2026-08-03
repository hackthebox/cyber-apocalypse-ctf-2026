import json
import os
import urllib.request

from foundpy import Contract, config, deploy_contract


DEFAULT_ORIGIN = "http://127.0.0.1:48334"
SETUP_ABI = [
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    }
]


def env(name):
    value = os.getenv(name)
    return value.strip() if value else None


def fetch_local_instance():
    req = urllib.request.Request(
        f"{DEFAULT_ORIGIN}/api/get-current-instance",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())

    rpc_url = data["0"]["RPC_URL"].replace("{ORIGIN}", f"{DEFAULT_ORIGIN}/api")

    return {
        "rpc_url": rpc_url,
        "privkey": data["1"]["PRIVKEY"],
        "setup": data["2"]["SETUP_CONTRACT_ADDR"],
    }


def load_config():
    rpc_url = env("RPC_URL")
    privkey = env("PRIVKEY") or env("PRIVATE_KEY")
    setup = env("SETUP_CONTRACT_ADDR") or env("SETUP")

    if rpc_url and privkey and setup:
        return {"rpc_url": rpc_url, "privkey": privkey, "setup": setup}

    print("[*] RPC_URL/PRIVKEY/SETUP_CONTRACT_ADDR not fully set; fetching local TCP1P instance")
    return fetch_local_instance()


instance = load_config()

config.setup(instance["rpc_url"], instance["privkey"])

setup = Contract(instance["setup"], abi=SETUP_ABI)

if setup.call("isSolved"):
    print("is solved:", True)
    raise SystemExit(0)

exploit = deploy_contract("Exploit.sol:PaleWaxExploit", instance["setup"])
exploit.send("investigate")

print("is solved:", setup.call("isSolved"))
