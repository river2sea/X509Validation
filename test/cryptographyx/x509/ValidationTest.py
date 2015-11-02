import os
import unittest

from cryptography import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from cryptographyx.x509.Validation import ListBackedCertificateLookup, \
    CertificateChain, ValidityPeriodRule, \
    BasicConstraintsRule, SignatureHashAlgorithmRule, \
SignatureVerificationRule, CompositeValidationRule, \
    ErrorCollectingContext, CertificateChainDelegate


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
    
    def verifySignature( self, issuerCertificate, signatureAlgorithm, toBeSigned ):
        publicKey = issuerCertificate.public_key
        HashAlgorithm = issuerCertificate.signature_hash_algorithm
        # verifier = publicKey.verifier( subjectSignature, HashAlgorithm )
        # verifier.update( data )
        # return verifier.verify()  
        return True      
        
        
class ValidationTest( unittest.TestCase ):
    
    def test_CertificateValidation( self ):
        testDirectory = os.path.dirname( __file__ )
        data = self.loadBinaryFile( os.path.join( testDirectory, 'CACertificate.der' ) )
        trustedCertificate = x509.load_der_x509_certificate( data, default_backend() )
        data = self.loadBinaryFile( os.path.join( testDirectory, 'UserCertificate.der' ) )
        untrustedCertificate = x509.load_der_x509_certificate( data, default_backend() )
        lookup = ListBackedCertificateLookup( [ trustedCertificate ] )
        delegate = TestCertificateChainDelegate()
        chain = CertificateChain( delegate, lookup, trustedRuleSet, untrustedRuleSet )
        context = ErrorCollectingContext()
        context.delegate = delegate
        isValid = chain.isValid( untrustedCertificate, context )
        if not isValid:
            print( 'context:', context )
        self.assertTrue( isValid, 'Certificate is invalid.' )
        
    def loadBinaryFile( self, path ):
        with open( path, 'rb' ) as inputFile:
            data = inputFile.read()  
            return data
        
