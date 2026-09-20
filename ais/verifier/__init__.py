"""Out-of-process verification service.

SENTINEL-AUDIT's job is to *independently* reproduce evidence. In-process that
independence is logical: the auditor reads only the audit chain, but it shares
address space with the components it audits. This package makes the separation
physical - the verifier runs as its own OS process, receives nothing but a
serialised audit chain, and returns an HMAC-signed verdict.
"""
