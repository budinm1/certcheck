#!/usr/bin/python3

# Copyright (C) Michal Budínský <michal@budinsky.net>
# GIT: https://github.com/budinm1/certcheck
# Licence: WTFPL, grab your copy here: http://www.wtfpl.net/

'''Check websites for valid SSL certificates.'''

import socket
import argparse
import json
import errno
from platform import system
from datetime import datetime, timezone
try:
    import ssl
except ImportError:
    badExit('Failed to import Python SSL library.')

VERSION = '1.0_rc1'
CONFIG_FILE = 'certcheck.urls'
NOW = datetime.now(timezone.utc)

# Linux output colors
red = '\033[91m'
green = '\033[92m'
yellow = '\033[93m'
noColor = '\033[0m'


def badExit(txt):
    '''In the case of nonstandard ending of program prints message
    and exit with status 1'''
    print(txt)
    exit(1)


def getUrlPort(rawURL):
    '''take URL in like 'exaple.com' or 'example.org:8080'
    and return it like list ['exaple.com', 443] or
    ['example.org', 8080]'''

    if ':' in rawURL:
        return(rawURL.split(':')[0], int(rawURL.split(':')[1].strip()))
    else:
        return(rawURL.strip(), 443)


def getUrls(rawURLs, url_file):
    '''If no URLs definet parse them from file.'''

    urls = []
    if not rawURLs:
        try:
            with open(url_file) as f:
                for line in f:
                    if '#' in line or len(line) < 3:
                        continue
                    else:
                        urls.append(getUrlPort(line))
        except OSError as e:
            if e.errno == errno.ENOENT:
                badExit('''FileNotFoundError: No URL argument specified
and provided url_file ('{}') not found.'''.format(url_file))
            else:
                raise

        except ValueError:
            badExit('''ValueError: Check your port numbers
in url_file ('{}').'''.format(url_file))
    else:
        for url in rawURLs:
            try:
                urls.append(getUrlPort(url))
            except ValueError:
                badExit('ValueError: Check your port numbers ')
    return urls


def report(url, port, errorsShort, errorsLong, indent=0, cert=None):
    '''Print program report in neat way.
    url, port of probed host
    errorsShort: short version of found errors, printed in []
    errorsLong: long descriptive version of errors
    indent: indentation of report acordingly to goDeep
    '''

    urlPort = url if port == 443 else '{}:{}'.format(url, port)

    if errorsShort:
        if args.json:
            print(json.dumps({
                'host': url,
                'port': port,
                'certificate': cert,
                'status': 'ERROR',
                'errors': {
                    'short': [msg for msg, col in errorsShort],
                    'long': errorsLong
                }
            }, sort_keys=True, indent=4))
        else:
            errorsShortColor = ' '.join([
                '{}{}{}'.format(col, msg, noColor)
                for msg, col in errorsShort])
            errorsShort = ' '.join([msg for msg, col in errorsShort])
            print('{ind}{url}{spaces}[ {msg} ]'.format(
                ind=' ' * indent,
                url=url,
                spaces=' ' * (75 - indent - len(urlPort) - len(errorsShort)),
                msg=errorsShortColor,
            ))
            if args.verbose:
                print(' ' * indent + '\n'.join(
                    [' ' * 2 + i for i in errorsLong]))
    elif not args.errors_only:
        if args.json:
            print(json.dumps({
                'host': url,
                'port': port,
                'certificate': cert,
                'status': 'OK',
                'errors': {
                    'short': [None],
                    'long': [None]
                }
            }, sort_keys=True, indent=4))
        else:
            print('{ind}{url}{spaces}[ {green}OK{noc} ]'.format(
                ind=' ' * indent,
                url=url,
                spaces=' ' * (73 - indent - len(urlPort)),
                green=green,
                noc=noColor
            ))


def checkCert(SSLContext, url, port=443, goDeep=True, indent=0, upSerial='',
              mainUrl=''):
    '''Main part of CerCheck program.
    url, port of probed host
    goDeep: used only on main host, will check, certificate consistency on all
    certificate DNS records
    indent: indentation of report acordingly to goDeep
    upSerial: serial number if main certificate
    '''

    errors_short = []
    errors_long = []

    try:
        conn = SSLContext.wrap_socket(socket.socket(socket.AF_INET),
                                      server_hostname=url)
        conn.connect((url, port))
        cert = conn.getpeercert()
        conn.close()

        not_after = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert['notAfter']),
            timezone.utc)
        not_before = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert['notBefore']),
            timezone.utc)
        serial_number = cert['serialNumber']

        if NOW.timestamp() - not_before.timestamp() < 0:
            errors_short.append(['NOT_BEFORE', red])
            errors_long.append('Not before: {}'.format(not_before))

        if not_after.timestamp() - NOW.timestamp() < 0:
            errors_short.append(['EXPIRED', red])
            errors_long.append('Not after: {}'.format(not_after))

        if (not_after - NOW).days < args.days_to_expire:
            errors_short.append(['EXPIRE_IN_{}_DAY{}'.format(
                (not_after - NOW).days, '' if (not_after - NOW) == 1 else 'S'),
                                 yellow])
            errors_long.append('Certificate will expire in {} days.'.format(
                (not_after - NOW).days))

        if args.no_alt_names:
            report(url, port, errors_short, errors_long, indent, cert)
        elif goDeep:
            report(url, port, errors_short, errors_long, indent, cert)
            subject_names = [host.replace('*.', '') for
                             dns, host in cert[
                                 'subjectAltName'] if host != url]

            mainUrl = url
            for url in subject_names:
                checkCert(SSLContext, url, 443, False, 2, serial_number,
                          mainUrl)
        else:
            if serial_number != upSerial:
                errors_short.append(['SERIAL_ERROR', yellow])
                errors_long.append(
                    'Certificate serial numbers of {} and {} do not match.\
                    '.format(mainUrl, url))
            report(url, port, errors_short, errors_long, indent, cert)

    except ssl.SSLError:
        errors_short.append(['SSL_ERROR', red])
        errors_long.append('General SSL error. \
OpenSSL is needed for this software to work.')
        report(url, port, errors_short, errors_long, indent)

    except ssl.CertificateError:
        errors_short.append(['CERTIFICATE_ERROR', red])
        errors_long.append('Certificate is probably not issued for this host')
        report(url, port, errors_short, errors_long, indent)

    except socket.timeout:
        errors_short.append(['TIMEOUT', red])
        errors_long.append('Connection timed out.')
        report(url, port, errors_short, errors_long, indent)

    except socket.gaierror:
        errors_short.append(['NOT_FOUND', yellow])
        errors_long.append('Host {} not found.'.format(url))
        report(url, port, errors_short, errors_long, indent)

    except OSError as e:
        if e.errno == errno.ECONNREFUSED:
            errors_short.append(['CONNECTION_REFUSED', red])
            errors_long.append('Connection on port {} refused.'.format(port))
            report(url, port, errors_short, errors_long, indent)
        else:
            raise

parser = argparse.ArgumentParser(
    description='''Check websites for valid SSL certificates.
Also checks all alt names in checked certificates.''')
parser.add_argument('-a', '--no_alt_names', default=False, action='store_true',
                    help='do not deep check alt names in certificates')
parser.add_argument('-e', '--errors_only', default=False, action='store_true',
                    help='do not report OK hosts')
parser.add_argument('-d', '--days_to_expire', default=21, type=int,
                    help='specify days to certificate expire, default 21')
parser.add_argument('-j', '--json', default=False, action='store_true',
                    help='print output in json, \
-j is  not affected by -e and -v ')
parser.add_argument('-n', '--no_color', default=False, action='store_true',
                    help='do not use colors in output')
parser.add_argument('-t', '--timeout', default=3, type=int,
                    help='specify request timeout in seconds, default 3.0')
parser.add_argument('-u', '--url_file', default=CONFIG_FILE,
                    help='specify file with URLs, only if no URL is specified')
parser.add_argument('-v', '--verbose', default=False,
                    action='store_true',
                    help='give also descriptive errors')
parser.add_argument('--version', default=False, action='store_true',
                    help='show version')
parser.add_argument('URL', help='list of URLs', nargs='*')
args = parser.parse_args()

if args.version:
    print('CertCheck version: {}'.format(VERSION))
    exit(0)

if args.no_color or system() != 'Linux':
    red = ''
    green = ''
    yellow = ''
    noColor = ''

hostUrls = getUrls(args.URL, args.url_file)

socket.setdefaulttimeout(args.timeout)
hostSSLContext = ssl.create_default_context()

for hostUrl, hostPort in hostUrls:
    checkCert(hostSSLContext, hostUrl, hostPort)
