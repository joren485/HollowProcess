HollowProcess
=============

Hollow Process / Dynamic Forking / RunPE injection technique implemented in Python 2.


A simple implementation of the well known Process Hollowing technique used by malware.
The idea to create this came from the excellent book Practical malware analysis.


Dependencies:

 - Pefile:
    install using: pip install pefile


Tests:
 - 32 bit payload into 32 bit target: NOT TESTED(but probably works)
 - 32 bit payload into 64 bit target: WORKS
 - 64 bit payload into 32 bit target: NOT TESTED (I do not know if this is actually possible)
 - 64 bit payload into 64 bit target: Creates 0xC0000005 error (Access Violation)

