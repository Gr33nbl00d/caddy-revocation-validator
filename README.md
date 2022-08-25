# Caddy Client Certificate Revocation Validator Plugin

This caddy plugin enables revocation check support for client certificates.
In your caddy json file revocation support can bet added by adding a validator to your client_authentication section.

# Features

* OCSP & CRL support
* OCSP response caching
* CRL stream based parsing to support CRLs with millions of entries
* Different CRL Storage modes
    * Memory based (Maximum performance, memory usage depends on crl size)
    * Persistent disk based via leveldb (High performance with minimal constant memory usage)
* CDP Support (CRL Distribution Point extension)
* Different CRL fetch modes (Fetch actively to not fail on first request)
* CRL Signature validation with different modes (fail/log/ignore)
* CRL CDP Strict modes to ensure if a CRL location is defined via CDP connection is only allowed if at least one entry was successfully checked
* OCSP AIA Strict modes to ensure if an OCSP server was defined in AIA connection is only allowed if at least one entry was successfully checked

# Motivation

After i found out that most webservers even the famous nginx are not really compliant to the official RFC specs My goal is to get a full RFC compliant high performant client certificate revocation
support which also supports big CRL list without running out of memory.

# Requirements

Caddy v2.5.2

# Getting started

The easiest way to use this plugin is to enable client revocation support via CDP and AIA certificate extensions. This requires that the client certificates has either CDP or AIA or both extensions
defined

Minimal config for OCSP and CRL support via CDP/AIA
```json
"client_authentication": {
    "trusted_ca_certs_pem_files": [
        "./certificates/ca.pem",
    ],
    "mode": "require_and_verify",
    "validators": [
        {
            "validator": "revocation",
            "mode": "prefer_ocsp",
            "crl_config": {
                "work_dir": "./crlworkdir"
            },
            "ocsp_config": {
                "default_cache_duration": "10m",
            }
        }
    ]
}
```

# Full Config Example

```json
"client_authentication": {
    "trusted_ca_certs_pem_files": [
        "./certificates/ca.pem",
    ],
    "mode": "require_and_verify",
    "validators": [
        {
            "validator": "revocation",
            "mode": "prefer_ocsp",
            "crl_config": {
                "work_dir": "./crlworkdir",
                "storage_type": "memory",
                "update_interval": "1m",
                "signature_validation_mode": "verify",
                "crl_files": [
                    "./customcrls/custom.crl.pem"
                ],
                "crl_urls": [
                    "http://myserver/custom.crl.pem"
                ],
                "trusted_signature_certs_files": [
                    "./certificates/customcacert.pem"
                ],
                "cdp_config": {
                    "crl_fetch_mode": "fetch_actively",
                    "crl_cdp_strict": true
                }
            },
            "ocsp_config": {
                "default_cache_duration": "1m",
                "trusted_responder_certs_files": [
                    "./certificates/responderca.crt"
                ],
                "ocsp_aia_strict": true
            }
        }
    ]
}
```

# Config Structure
## mode
Defines the "Revocation Check Mode"

Possible Values:
>prefer_ocsp
> 
> Description: Prefer to check OCSP server but also check CRL if no OCSP server is known or can be accessed

>prefer_crl
> 
> Description: Prefer to check CRL but also check OCSP server if no CRL is known or can be accessed

>ocsp_only 
>
> Description: Only check OCSP servers if present, ignores all CRLs defined by CDP or config

>crl_only
>
> Description: Only check CRLs if present, ignores all OCSP servers defined by AIA or config

## crl_config
Configures the CRL checking
### work_dir
Configures the working directory for temporary CRL downloads and for disk based persistent CRLs
### storage_type
Configures how to store CRLs
Possible Values:
>memory
>
> Description: Stores CRL entries in a memory based map (very fast but memory consumption of caddy depends on CRL size).
> For most use cases CRLs do not grow that much, it should be ok for most use cases
> Memory usage of caddy for a CRL with 1 million entries is about 500mb
> This is recommended for systems with typical sized CRLs and typical server memory  

>disk
>
> Description: Stores CRL entries in a level db based file (still fast but slower than memory).
> Access times measured for a 1 million entry CRL was 1 millisecond
> Memory usage of caddy is not dependent on CRL size
> This is recommended for systems with giant CRLs or servers with low memory

### update_interval
The interval in which the already known CRLs will be updated.
Valid time units are “ns”, “us” (or “µs”), “ms”, “s”, “m”, “h”

See: https://pkg.go.dev/time#ParseDuration

### signature_validation_mode
Configures the signature validation or the CRL

Possible Values:
>none
>
> Description: Do not verify the signature

>verify
>
> Description: Verifies the signature during CRL parsing. Will not accept CRL if validation failed

>verify_log
>
> Description: Verifies the signature during CRL parsing. Will log a warning if the signature validation failed but will still accept the CRL


### crl_urls 
A predefined list of http(s) urls pointing to CRLs. These lists will be checked for all client certificates.
The predefined CRLs will be loaded on startup and updated cyclic.
PEM and DER encoding are both supported

### crl_files
A predefined list of files pointing to CRLs. These lists will be checked for all client certificates.
The predefined CRLs will be loaded on startup
PEM and DER encoding are both supported

### trusted_signature_certs_files
A predefined list of files of CA certificates which are trusted for CRL signing.
These certificates will be used to verify CRL signature if the CRL signature cert is not part of the client cert chain
PEM and DER encoding are both supported

### cdp_config
Configures how CDP entries are used

#### crl_fetch_mode
Possible Values:
>fetch_actively
>
> Description: If a CRL defined in a client cert CDP is not known/loaded during handshake
> it is downloaded and the client connection will wait till the download and parsing is finished
> Also other clients connecting in the same time with the same CDP will wait for the download of the first connection to finish

>fetch_background
>
> Description: If a CRL defined in a client cert CDP is not known/loaded during handshake download will be triggered in background

#### crl_cdp_strict
In strict mode it is required that if a CDP is defined inside the certificate.
The CRL needs to be downloaded from one of the CDP locations and needs to be checked to gain access
If the CRL can not be downloaded, the validation of the crl signature failed (see signature_validation_mode),
or the CRL is not downloaded yet (see crl_fetch_mode) connection is denied.

## ocsp_config
### default_cache_duration
The default time to cache OCSP responses valid time units are “ns”, “us” (or “µs”), “ms”, “s”, “m”, “h”
If the default time is zero no caching will be performed.
If the OCSP responder has defined a "NextUpdate" time the caching time will be time from now on till the next update,
in this case default_cache_duration will be ignored

### ocsp_aia_strict
In strict mode it is required that if an OCSP server is defined inside AIA extension at least
one OCSP server defined can be contacted to check for revocation. Or a valid response of one of the OCSP server is inside the cache 
If no OCSP server can be contacted and no cached response is present or the validation of the OCSP response signature failed connection is denied.

## Todos:

Some features are still missing:

* LDAP Support for CDPs in CRLs is missing
* Allow overriding of OCSP locations and CRL locations via config
* Check CRL nextupdate field if the CRL is outdated/make configurable what to do / allow grace time
* Support AIA extension to retrieve certificate from url if defined (CRL+OCSP)
* OCSP Caching is not fully compliant with RFC 5019 Setion 6 - Caching Recommendations as HTTP caching directives are not used
* Check freshness of ocsp response by checking nextUpdate value if present. If outdated make configurable what to do / allow grace time

Some technical debt:

* Add Unit Tests
* Add automatic Integration Tests
* CI/CD
* Static Code Analysis
* Automatic dependency updates
