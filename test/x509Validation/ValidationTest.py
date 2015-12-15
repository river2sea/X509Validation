import datetime
import sys
import traceback
import unittest

from cryptography import *
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from .Rule import CompositeValidationRule, ValidityPeriodRule, \
    BasicConstraintsRule, SignatureHashAlgorithmRule, SignatureVerificationRule, \
    KeyUsageExtensionRule, CertificateRevocationListRule
from .Validation import CertificateChainDelegate, \
    ListBackedCertificateLookup, CertificateChain, \
    CertificateRevocationListLookup


#xyz = x509.KeyUsage(digital_signature, content_commitment, key_encipherment, data_encipherment, key_agreement, key_cert_sign, crl_sign, encipher_only, decipher_only)
trustedKeyUsage = x509.KeyUsage( 
    False,  # digital_signature
    False,  # content_commitment
    False,  # key_encipherment
    False,  # data_encipherment
    False,  # key_agreement
    True,  # key_cert_sign
    True,  # crl_sign
    False,  # encipher_only
    False  # decipher_only
 )

untrustedKeyUsage = x509.KeyUsage( 
    True,  # digital_signature
    True,  # content_commitment (aka non_repudiation)
    True,  # key_encipherment
    True,  # data_encipherment
    False,  # key_agreement
    False,  # key_cert_sign
    False,  # crl_sign
    False,  # encipher_only
    False  # decipher_only    
 )

trustedRuleSet = CompositeValidationRule( name = "Trusted Rule Set")
trustedRuleSet.addRule( ValidityPeriodRule() )
trustedRuleSet.addRule( BasicConstraintsRule( True, 1 ) )
trustedRuleSet.addRule( KeyUsageExtensionRule( trustedKeyUsage ) )
trustedRuleSet.addRule( SignatureHashAlgorithmRule( hashes.SHA256 ) )
# trustedRuleSet.addRule( CriticalExtensionsRule() )         
trustedRuleSet.addRule( SignatureVerificationRule() )
    
untrustedRuleSet = CompositeValidationRule( name = "Untrusted Rule Set" )
untrustedRuleSet.addRule( ValidityPeriodRule() )
untrustedRuleSet.addRule( BasicConstraintsRule( False, 0 ) )
untrustedRuleSet.addRule( KeyUsageExtensionRule( untrustedKeyUsage ) )
untrustedRuleSet.addRule( SignatureHashAlgorithmRule( hashes.SHA256 ) )
# untrustedRuleSet.addRule( CriticalExtensionsRule() )         
untrustedRuleSet.addRule( SignatureVerificationRule() )
       
crlRuleSet = CompositeValidationRule( name = "CRL Rule Set" )
crlRuleSet.addRule( ValidityPeriodRule() )
crlRuleSet.addRule( BasicConstraintsRule( False, 0 ) )
crlRuleSet.addRule( KeyUsageExtensionRule( untrustedKeyUsage ) )
crlRuleSet.addRule( SignatureHashAlgorithmRule( hashes.SHA256 ) )
# crlRuleSet.addRule( CriticalExtensionsRule() )         
crlRuleSet.addRule( SignatureVerificationRule() )


def dumpTraceback():
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb( exc_traceback, limit=1, file=sys.stdout )
    traceback.print_exception( exc_type, exc_value, exc_traceback, file=sys.stdout )
   
           
class TestCertificateChainDelegate( CertificateChainDelegate ):
    
    def __init__( self ):
        self._errors = []
        
    @property
    def errors( self ):
        return self._errors
    
    def currentTime( self ):
        return datetime.datetime.now()

    def verifySignature( self, issuerCertificate, subjectCertificate ):
        '''
        This test is assuming a signature algorithm of sha256WithRSAEncryption/null-parameters.
        '''
        try:
            # print( 'Verifying the signature of the subject certificate({0}) with the issuerCertificate({1})...'.format( subjectCertificate, issuerCertificate ) )
            issuerPublicKey = issuerCertificate.public_key()
            hashAlgorithm = subjectCertificate.signature_hash_algorithm
            tbsCertificate = subjectCertificate.tbs_certificate_bytes
            subjectSignature = subjectCertificate.signature
            padding = PKCS1v15()
            verifier = issuerPublicKey.verifier( subjectSignature, padding, hashAlgorithm )
            verifier.update( tbsCertificate )
            verifier.verify()
            return True
        except InvalidSignature:
            return False          
        except Exception as e:
            raise e
                
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
    
    def dumpErrors( self ):   
        for error in self.errors:
            print( error )
            

class TestCRLLookup( CertificateRevocationListLookup ):       
    
    def __init__( self ):
        self._serialNumbers = []
        
    def addSerialNumber( self, serialNumber ):
        self._serialNumbers.append( serialNumber )
        
    def certificateIsListed( self, serialNumber ):
        if serialNumber in self._serialNumbers:
            return True
        return False
    
     
class ValidationTest( unittest.TestCase ):
    
    @classmethod
    def setUpClass( cls ):
        trustedCertificates = []
        trustedCertificate = cls.loadDERCertifcate( 'data/PKITS/certs/TrustAnchorRootCertificate.crt' )
        trustedCertificates.append( trustedCertificate )
        trustedCertificate = cls.loadDERCertifcate( 'data/PKITS/certs/GoodCACert.crt' )
        trustedCertificates.append( trustedCertificate )        
        trustedCertificate = cls.loadDERCertifcate( 'data/PKITS/certs/GoodsubCACert.crt' )
        trustedCertificates.append( trustedCertificate )        
        cls.lookup = ListBackedCertificateLookup( trustedCertificates )

    @classmethod
    def loadDERCertifcate( cls, path ):
        with open( path, 'rb' ) as inputFile:
            data = inputFile.read()  
            certificate = x509.load_der_x509_certificate( data, default_backend() )
            return certificate
                
    def test_GoodCertificateValidation( self ):
        untrustedCertificate = ValidationTest.loadDERCertifcate( 'data/PKITS/certs/ValidCertificatePathTest1EE.crt' )
        delegate = TestCertificateChainDelegate() 
        chain = CertificateChain( delegate, ValidationTest.lookup, trustedRuleSet, untrustedRuleSet )
        isValid = chain.isValid( untrustedCertificate ) 
        if not isValid:
            delegate.dumpErrors()           
        self.assertTrue( isValid, 'Certificate is invalid.' )
        
    def test_BadCertificateValidation( self ):
        untrustedCertificate = ValidationTest.loadDERCertifcate( 'data/PKITS/certs/BadSignedCACert.crt' )
        delegate = TestCertificateChainDelegate() 
        chain = CertificateChain( delegate, ValidationTest.lookup, trustedRuleSet, trustedRuleSet )
        isValid = chain.isValid( untrustedCertificate )  
        if isValid:
            delegate.dumpErrors()   
        self.assertTrue( not isValid, 'Certificate is valid, expected invalid.' )
        
    def test_CRLLookup( self ):
        untrustedCertificate = ValidationTest.loadDERCertifcate( 'data/PKITS/certs/ValidCertificatePathTest1EE.crt' )
        crlLookup = TestCRLLookup()
        crlLookup.addSerialNumber( untrustedCertificate.serial )
        crlRuleSet.addRule( CertificateRevocationListRule( crlLookup ) )
        delegate = TestCertificateChainDelegate() 
        chain = CertificateChain( delegate, ValidationTest.lookup, trustedRuleSet, crlRuleSet )
        isValid = chain.isValid( untrustedCertificate )  
        self.assertTrue( not isValid, 'Certificate is valid, expected invalid (on CRL).' )


if __name__ == "__main__":
    unittest.main()
    