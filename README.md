# CertCheck
Check websites for valid SSL certificates. Also checks all alt names in checked certificates.

## Usage
```shell
certcheck.py [-h] [-a] [-e] [-d DAYS_TO_EXPIRE] [-j] [-n] [-t TIMEOUT]
[-u URL_FILE] [-v] [--version] [URL [URL ...]]

positional arguments:
URL                   list of URLs

optional arguments:
-h, --help            show this help message and exit
-a, --no_alt_names    do not deep check alt names in certificates
-e, --errors_only     do not report OK hosts
-d DAYS_TO_EXPIRE, --days_to_expire DAYS_TO_EXPIRE
                      specify days to certificate expire, default 10
-j, --json            print report in json, not affected by -e and -v
-n, --no_color        do not use colors in output
-t TIMEOUT, --timeout TIMEOUT
                      specify request timeout in seconds, default 3.0
-u URL_FILE, --url_file URL_FILE
                      specify file with URLs, only if no URL is specified
-v, --verbose         give also descriptive errors
--version             show version
```

## Raised errors

### NOT_BEFORE
certificate issued in the future

### EXPIRED
certificate expired

### SOON_EXPIRED
certificate will expire in -d days, default in 10 days

### SERIAL_ERROR
certificate serial number on alt name is not the same as in main certificate

### NOT_FOUND
hostname not found

### CONNECTION_REFUSED
connection to hostname refusee

### SSL_ERROR
SSL error, certificate is not issued for this host, usualy

### CERTIFICATE_ERROR
certificate is probably not issued for this host

### TIMEOUT
connection time out

### Licence
WTFPL, grab your copy here: http://www.wtfpl.net/

Copyright (C) Michal Budínský <michal@budinsky.net>
