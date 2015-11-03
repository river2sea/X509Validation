# X509Validation
A python implementation of the X.509v3 certificate path validation algorithm, 
built on top of pyca's 'cryptography' package.

This is a work in progress. The pyca/cryptography team is currently working on exposing the necessary properties on x509.Certificate that will allow users to verify the signature on a certificate.

The basic path validation functionality will be implemeted first, as much as is necessary to implement a closed-system (i.e. we are the CA and control all certificate parameters) PKI for www.peacekeeper.org v2.



