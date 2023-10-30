import sys
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.dcerpc.v5.dcomrt import IObjectExporter

def main(argv):
    if len(argv) != 1:
        print("Usage: python script.py <IP address>")
        sys.exit(2)

    target = f"ncacn_ip_tcp:{argv[0]}"
    rpcTransport = transport.DCERPCTransportFactory(target)

    portmap = rpcTransport.get_dce_rpc()
    portmap.set_auth_level(RPC_C_AUTHN_LEVEL_NONE)
    portmap.connect()

    obj = IObjectExporter(portmap)

    bindings = obj.ServerAlive2()

    for binding in bindings:
        addr = binding['aNetworkAddr']
        print(f"Address: {addr}")

if __name__ == "__main__":
    main(sys.argv[1:])