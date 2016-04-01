#!/usr/bin/python3

# Copyright (C) Michal Budínský <michal@budinsky.net>
# GIT: https://github.com/budinm1/certcheck
# Licence: WTFPL, grab your copy here: http://www.wtfpl.net/

'''Check websites for valid SSL certificates.'''

import ssl
import socket
import argparse

CONFIG_FILE = 'certcheck.urls'


def badExit(txt):
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
        except FileNotFoundError:
            badExit('''FileNotFoundError: No URL argument specified
and provided url_file ('{}') not found.'''.format(url_file))
        except ValueError:
            badExit('''ValueError: Check your port numbers
in url_file ('{}').'''.format(url_file))
    else:
        for url in rawURLs:
            try:
                urls.append(getUrlPort(url))
            except ValueError:
                badExit('ValueError: Check your port numbers ')
    return(urls)

parser = argparse.ArgumentParser(
    description='Check websites for valid SSL certificates.')
parser.add_argument('-u', '--url_file',
                    help='specify file with URLs, only if no URL is specified',
                    default=CONFIG_FILE)
parser.add_argument('URL', help='list of URLs', nargs='*')
args = parser.parse_args()

urls = getUrls(args.URL, args.url_file)
context = ssl.create_default_context()

for url, port in urls:
    conn = context.wrap_socket(socket.socket(socket.AF_INET),
                               server_hostname=url)
    conn.connect((url, port))
    cert = conn.getpeercert()
    conn.close()
    import pprint
    pprint.pprint(cert)
