from abc import ABCMeta, abstractmethod
import sys

from cryptography import x509

# TODO: Put this somewhere more appropriate.
#
def extensionInCertificate( oid, certificate ):
    for extension in certificate.extensions:
        if extension.oid == oid:
            return True
    return False
        
        
class CertificateValidationRule( metaclass = ABCMeta ):
    '''
    The base class for all validation rules.
    '''
    
    @abstractmethod
    def isValid( self, certificate, context ):
        '''
        Returns a RuleResult.
        '''
        pass
    
    def __str__( self ):
        return self.__class__.__name__

    def __repr__( self ):
        return self.__str__()
    
    
class CompositeValidationRule( CertificateValidationRule ):
    '''
    A CertificateValidationRule that aggregates an ordered list
    of CertificateValidationRule and applies them in order to
    the certificate passed to isValid(...).
    
    This class is used to build rule sets.
    
    If PathValidationContext.failEarly is True, then this
    collection of rules will raise a CertificateException on
    the first rule that fails.
    
    If False, all rules will be executed and failures will
    be passed to PathValidationContext.ruleFailed().
    
    ErrorCollectingContext will collect all
    failures in ErrorCollectingContext.errors.
    '''
    def __init__( self ):
        self._rules = []
        
    def addRule( self, rule ):
        self._rules.append( rule )
        
    def isValid( self, certificate, context ):
        
        for rule in self._rules:
            
            if context.failed and context.failNow:
                return RuleResult( False )
            
            result = None 
            
            try:
                result = rule.isValid( certificate, context )
            except Exception:
                # TODO: capture stack trace, log with logging...
                print( sys.exc_info() )
                context.log.error( sys.exc_info() )  
                result = RuleResult( False, errorMessage = str( sys.exc_info() ) ) 

            if result.isValid:
                continue
            else:
                context.failed = True
                context.delegate.ruleFailed( result )
                if context.delegate.shouldFailEarly():
                    context.failNow = True
        
        return RuleResult( True )
    
                
class RuleResult( object ):
    '''
    TODO: Add positional 'certificate' parameter after 'isValid'.
          Get the serial number and store it in _serialNumber.
          Create a serialNumber property, and add it to __str__().
    '''
    def __init__( self, isValid, errorMessage = None, certificate = None ):
        self._isValid = isValid
        self._certificate = certificate
        self._errorMessage = errorMessage
        
    @property
    def isValid( self ): 
        return self._isValid

    @property
    def certificate( self ): 
        return self._certificate
    
    @property
    def errorMessage( self ):
        return self._errorMessage
    
    def __str__( self ):
        return 'isValid={0} : errorMessage={1} : certificate={2}'.format( self.isValid, self.errorMessage, self.certificate )
    
    def __repr__( self ):
        return self.__str__()
    
    
class BasicConstraintsRule( CertificateValidationRule ):
    '''
    4.2.1.9.  Basic Constraints

       The basic constraints extension identifies whether the subject of the
       certificate is a CA and the maximum depth of valid certification
       paths that include this certificate.
    
       The cA boolean indicates whether the certified public key may be used
       to verify certificate signatures.  If the cA boolean is not asserted,
       then the keyCertSign bit in the key usage extension MUST NOT be
       asserted.  If the basic constraints extension is not present in a
       version 3 certificate, or the extension is present but the cA boolean
       is not asserted, then the certified public key MUST NOT be used to
       verify certificate signatures.
    
       The pathLenConstraint field is meaningful only if the cA boolean is
       asserted and the key usage extension, if present, asserts the
       keyCertSign bit (Section 4.2.1.3).  In this case, it gives the
       maximum number of non-self-issued intermediate certificates that may
       follow this certificate in a valid certification path.  (Note: The
       last certificate in the certification path is not an intermediate
       certificate, and is not included in this limit.  Usually, the last
       certificate is an end entity certificate, but it can be a CA
       certificate.)  A pathLenConstraint of zero indicates that no non-
       self-issued intermediate CA certificates may follow in a valid
       certification path.  Where it appears, the pathLenConstraint field
       MUST be greater than or equal to zero.  Where pathLenConstraint does
       not appear, no limit is imposed.
    
       Conforming CAs MUST include this extension in all CA certificates
       that contain public keys used to validate digital signatures on
       certificates and MUST mark the extension as critical in such
       certificates.  This extension MAY appear as a critical or non-
       critical extension in CA certificates that contain public keys used
       exclusively for purposes other than validating digital signatures on
       certificates.  Such CA certificates include ones that contain public
       keys used exclusively for validating digital signatures on CRLs and
       ones that contain key management public keys used with certificate
       enrollment protocols.  This extension MAY appear as a critical or
       non-critical extension in end entity certificates.
    
       CAs MUST NOT include the pathLenConstraint field unless the cA
       boolean is asserted and the key usage extension asserts the
       keyCertSign bit.
       
       TODO: We need to know if the key usage extension includes keyCertSign.
   '''    
    def __init__( self , mustBeCA, pathLength ):
        self._mustBeCA = mustBeCA
        self._pathLength = pathLength
        
    def isValid( self, certificate, context ):
        
        passed = False
        caMessage = ''
        pathLengthMessage = ''
        errorMessage = None
        basicConstraints = None
        keyCertSign = False
        
        if extensionInCertificate( x509.oid.ExtensionOID.BASIC_CONSTRAINTS, certificate ):
            basicConstraints = certificate.extensions.get_extension_for_oid( x509.oid.ExtensionOID.BASIC_CONSTRAINTS )
            
        if extensionInCertificate( x509.oid.ExtensionOID.KEY_USAGE, certificate ):
            keyUsage = certificate.extensions.get_extension_for_oid( x509.oid.ExtensionOID.KEY_USAGE )
            keyCertSign = keyUsage.value.key_cert_sign

        if basicConstraints is not None:
            
            if basicConstraints.value.ca is not None:
                if basicConstraints.value.ca == self._mustBeCA:
                    passed = True
                else:
                    caMessage = 'The "ca" constraint is present and true, but is required to be false.'
            else:
                # The ca constraint is absent.
                #
                if not self._mustBeCA:
                    passed = True
                else:
                    caMessage = 'The "ca" constraint is absent but is requied to be present and true.'
                    
            if basicConstraints.value.path_length is not None:
                if keyCertSign and basicConstraints.value.ca:
                    if context.currentPathLength <= basicConstraints.value.path_length:
                        passed = True
                    else:
                        pathLengthMessage = 'The "pathLength" constraint is present ({0}) and has been exceeded.'.format( basicConstraints.value.path_length )
                else:
                        pathLengthMessage = 'The "pathLength" constraint is present ({0}) - Invalid keyCertSign({1}) and/or ca({2}).'.format( 
                                                basicConstraints.value.path_length, keyCertSign, basicConstraints.value.ca )
            else:
                # No limit if pathLength is absent.
                #
                passed = True
            
        else:
            # The BasicConstraints basicConstraints is absent.
            # Nothing to do for pathLength.
            #
            if not self._mustBeCA:
                passed = True
            else:
                caMessage = 'The BasicConstraints basicConstraints is absent, and the "ca" constraint is required to be present and true.'
    
            if not passed:
                errorMessage = caMessage + ' ' + pathLengthMessage
            
        if passed:
            return RuleResult( passed )
        else:
            return RuleResult( passed, errorMessage = errorMessage, certificate = certificate )
    

class ValidityPeriodRule( CertificateValidationRule ):
    
    def isValid( self, certificate, context ):
        currentTime = context.delegate.currentTime()
        valid = currentTime >= certificate.not_valid_before or currentTime < certificate.not_valid_after
        if valid:
            return RuleResult( valid )
        else:
            return RuleResult( valid,
                               errorMessage = '{0} is not within {1} - {2}.'.format( currentTime,
                               certificate.not_valid_before, certificate.not_valid_after ), certificate = certificate )
    
    
class SignatureHashAlgorithmRule( CertificateValidationRule ):
    
    def __init__( self, hashAlgorithm ):
        self._hashAlgorithm = hashAlgorithm
        
    def isValid( self, certificate, context ):
        valid = self.hashAlgorithmsMatch( certificate.signature_hash_algorithm, self._hashAlgorithm )
    
        if valid:
            return RuleResult( valid )
        else:
            return RuleResult( valid,
                               errorMessage = 'Expected {0}, found {1}.'.format( self._hashAlgorithm, certificate.signature_hash_algorithm ),
                               certificate = certificate )
        
    def hashAlgorithmsMatch( self, a, b ):
        return a.block_size == b.block_size and a.digest_size == b.digest_size and a.name == b.name
    

class SignatureVerificationRule( CertificateValidationRule ):
    
    def isValid( self, certificate, context ):
        try:
            issuerCertificate = context.chain.findCertificateFor( certificate.issuer )
            valid = context.delegate.verifySignature( issuerCertificate, certificate )
            if valid:
                return RuleResult( valid )
            else:
                return RuleResult( valid, errorMessage = 'Signature verification failed.', certificate = certificate )
        except Exception as e:
            print( sys.exc_info() )
            return RuleResult( valid, errorMessage = 'Signature verification failed: {0}'.format( str( e ) ), certificate = certificate )
    
    
class KeyUsageExtensionRule( CertificateValidationRule ):
    
    def __init__( self, allowedUsage ):
        self._allowedUsage = allowedUsage
        
    def isValid( self, certificate, context ):
        '''
        If an item in allowedUsage is True, then the corresponding item in the extension MAY(?) be True or False.
        If an item in allowedUsage is False, then the corresponding item in the extension MUST be False.
        '''
        keyUsage = certificate.extensions.get_extension_for_oid( x509.oid.ExtensionOID.KEY_USAGE ).value
        valid = self.usagesAreEqual( keyUsage, self._allowedUsage )
        
        if not valid:
            keyUsageBits = self.keyUsageAsPseudoBits( keyUsage )
            allowedUsageBits = self.keyUsageAsPseudoBits( self._allowedUsage )
            
            return RuleResult( valid,
                               errorMessage = keyUsageBits + ' : ' + allowedUsageBits + ' : ' + 'keyUsage({0}) is not equal to allowedUsage({1})'.format( keyUsage, self._allowedUsage ),
                               certificate = certificate )
        else:
            return RuleResult( valid, None )
        
    def usagesAreEqual( self, keyUsageA, keyUsageB ):
        itemsA = self.keyUsageItems( keyUsageA )
        itemsB = self.keyUsageItems( keyUsageB )
        return itemsA == itemsB
    
    def keyUsageItems( self, keyUsage ):
        items = [ 
           keyUsage.digital_signature,
           keyUsage.content_commitment,
           keyUsage.key_encipherment,
           keyUsage.data_encipherment,
           keyUsage.key_agreement,
           keyUsage.key_cert_sign,
           keyUsage.crl_sign ]
        
        if keyUsage.key_agreement:
            items.append( keyUsage.encipher_only )
            items.append( keyUsage.decipher_only )
        
        return items

    def keyUsageAsPseudoBits( self, keyUsage ):
        items = self.keyUsageItems( keyUsage )
        bits = []
        for item in items:
            if item:
                bits.append( '1' )
            else:
                bits.append( '0' )
        return ''.join( bits )

        
class CriticalExtensionsRule( CertificateValidationRule ):

    def isValid( self, certificate, context ):
        for extension in certificate.extensions:
            if extension.critical:
                pass
            
        return RuleResult( False, errorMessage = 'Not Implemented!', certificate = certificate )
            
 
class SubjectAlternativeNameRule( CertificateValidationRule ):
    '''
    TODO: Enforce standard name content constraints.
    
    @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    '''    
    def isValid( self, certificate, context ):
        if certificate.subject is None:
            # The subject alternate name MUST be present.
            if extensionInCertificate( x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME, certificate ):
                altName = certificate.extensions.get_extension_for_oid( x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME )
                # TODO: Check structure of name...
            else:
                return RuleResult( False,
                                   errorMessage = 'subjectAltName({0} is required but absent.'.format( x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME ),
                                   certificate = certificate )
            
        return RuleResult( True )
        

class CertificateRevocationListRule( CertificateValidationRule ):
    
    def __init__( self, crlLookup ):
        self._crlLookup = crlLookup
        
    def isValid( self, certificate, context ):
        if self._crlLookup.certificateIsListed( certificate.serial_number ):
            return RuleResult( False,
                               errorMessage = 'Certificate {0} : {1} is revoked.'.format( certificate.subject, certificate.serial_number ),
                               certificate = certificate )
        else:
            return RuleResult( True )
                          
            
                                   
