# xnyss
Implementation of the eXtended Naor-Yung Signature Scheme. It was specifically 
designed for use in blockchain technologies.

XNYSS uses a modified form of Naor-Yung chaining to transform a One-Time 
Signature (OTS) scheme into a many-time scheme. This is achieved by including 
the hashes of two public keys, to be used for future signatures, in every 
created signature. Thus every signature in the resulting binary tree can be 
traced back to the first one.

This implementation is part of my master's thesis, which will (hopefully) be 
finished and made public in August of this year.
