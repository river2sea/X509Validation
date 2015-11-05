import datetime
import os
import sys
import unittest

from cryptography import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der import decoder
from pyasn1_modules.rfc2459 import SubjectPublicKeyInfo

from cryptographyx.x509.Rule import CompositeValidationRule, ValidityPeriodRule, \
    BasicConstraintsRule, SignatureHashAlgorithmRule, SignatureVerificationRule
from cryptographyx.x509.Validation import CertificateChainDelegate, \
    ListBackedCertificateLookup, CertificateChain


trustedKeyUsage = x509.KeyUsage( 
    True,  # digital_signature
    True,  # content_commitment
    True,  # key_encipherment
    False,  # data_encipherment
    False,  # key_agreement
    True,  # key_cert_sign
    True,  # crl_sign
    False,  # encipher_only
    False  # decipher_only    
 )
        
untrustedKeyUsage = x509.KeyUsage( 
    True,  # digital_signature
    True,  # content_commitment
    True,  # key_encipherment
    False,  # data_encipherment
    True,  # key_agreement
    False,  # key_cert_sign
    False,  # crl_sign
    False,  # encipher_only
    False  # decipher_only
 )

trustedRuleSet = CompositeValidationRule()
trustedRuleSet.addRule( ValidityPeriodRule() )
trustedRuleSet.addRule( BasicConstraintsRule( True, 1 ) )
# trustedRuleSet.addRule( KeyUsageExtensionRule( trustedKeyUsage ) )
trustedRuleSet.addRule( SignatureHashAlgorithmRule( hashes.SHA256 ) )
# trustedRuleSet.addRule( CriticalExtensionsRule() )         
trustedRuleSet.addRule( SignatureVerificationRule() )
    
untrustedRuleSet = CompositeValidationRule()
untrustedRuleSet.addRule( ValidityPeriodRule() )
untrustedRuleSet.addRule( BasicConstraintsRule( False, 0 ) )
# untrustedRuleSet.addRule( KeyUsageExtensionRule( untrustedKeyUsage ) )
untrustedRuleSet.addRule( SignatureHashAlgorithmRule( hashes.SHA256 ) )
# untrustedRuleSet.addRule( CriticalExtensionsRule() )         
untrustedRuleSet.addRule( SignatureVerificationRule() )
        
        
class TestCertificateChainDelegate( CertificateChainDelegate ):
    
    def __init__( self ):
        self._errors = []
        
    def currentTime( self ):
        return datetime.datetime.now()

    def verifySignature( self, issuerCertificate, subjectCertificate ):
        '''
        This test is assuming a signature algorithm of sha256WithRSAEncryption/null-parameters.
        '''
        try:
            print( 'Verifying the signature of the subject certificate({0}) with the issuerCertificate({1})...'.format( subjectCertificate, issuerCertificate ) )
            issuerPublicKey = issuerCertificate.public_key()
            # Use the following to access the signatureAlgorithm and parameters. It would be nice
            # if we could get this directly from the x509.Certificate.
            # spkiEncoding = subjectCertificate.public_key().public_bytes( Encoding.DER, PublicFormat.SubjectPublicKeyInfo )
            # subjectPublicKeyInfo = decoder.decode( spkiEncoding, SubjectPublicKeyInfo() )
            hashAlgorithm = subjectCertificate.signature_hash_algorithm
            tbsCertificate = subjectCertificate.tbs_certificate_bytes
            subjectSignature = subjectCertificate.signature
            # verifier = issuerPublicKey.verifier( subjectSignature, padding.PSS( mgf = padding.MGF1( hashAlgorithm ), salt_length = padding.PSS.MAX_LENGTH ), hashAlgorithm )
            padding = PKCS1v15()
            verifier = issuerPublicKey.verifier( subjectSignature, padding, hashAlgorithm )
            verifier.update( tbsCertificate )
            verifier.verify()
        except Exception as e:
            print( sys.exc_info() )
            # TODO: Log the exception info.
            return False
        
        return True
          
        
    def ruleFailed( self, ruleResult ):
        self._errors.append( ruleResult )
    
    def shouldFailEarly( self ):
        '''
        Return True if path validation should abort when the first
        rule fails, or if it should continue processing the certificate
        so we can gather all of the errors in the certificate when it
        contains more than one defect.
        '''
        return False
    
            
class ValidationTest( unittest.TestCase ):
    
    def test_CertificateValidation( self ):

        trustedCertificates = []
        data = self.loadBinaryFile( 'data/PKITS/certs/TrustAnchorRootCertificate.crt' )
        trustedCertificate = x509.load_der_x509_certificate( data, default_backend() )
        trustedCertificates.append( trustedCertificate )
        data = self.loadBinaryFile( 'data/PKITS/certs/GoodCACert.crt' )
        trustedCertificate = x509.load_der_x509_certificate( data, default_backend() )
        trustedCertificates.append( trustedCertificate )        
        data = self.loadBinaryFile( 'data/PKITS/certs/GoodsubCACert.crt' )
        trustedCertificates.append( trustedCertificate )        
        lookup = ListBackedCertificateLookup( trustedCertificates )

        data = self.loadBinaryFile( 'data/PKITS/certs/ValidCertificatePathTest1EE.crt' )
        untrustedCertificate = x509.load_der_x509_certificate( data, default_backend() )  
              
        delegate = TestCertificateChainDelegate() 
        chain = CertificateChain( delegate, lookup, trustedRuleSet, untrustedRuleSet )
        isValid = chain.isValid( untrustedCertificate )            
        self.assertTrue( isValid, 'Certificate is invalid.' )
        
    def loadBinaryFile( self, path ):
        with open( path, 'rb' ) as inputFile:
            data = inputFile.read()  
            return data
        
