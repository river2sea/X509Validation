from abc import ABCMeta, abstractmethod
import datetime
import sys

from cryptography import x509


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
            
            if context.failNow:
                return RuleResult( False )
            
            result = None 
            
            try:
                result = rule.isValid( certificate, context )
            except Exception:
                # TODO: capture stack trace, log with logging...
                context.log.error( sys.exc_info() )  
                result = RuleResult( False, errorMessage =  str( sys.exc_info() ) ) 

            if result.isValid:
                continue
            else:
                context.delegate.ruleFailed( result  )
                if context.delegate.shouldFailEarly():
                    context.failNow = True
        
        return RuleResult( True )
    
                
class RuleResult( object ):
    
    def __init__( self, isValid, errorMessage = None ):
        self._isValid = isValid
        self._errorMessage = errorMessage
        
    @property
    def isValid( self ): 
        return self._isValid

    @property
    def errorMessage( self ):
        return self._errorMessage
    
    def __str__( self ):
        return 'isValid={0} : errorMessage={1}'.format( self.isValid, self.errorMessage )
    
    def __repr__( self ):
        return self.__str__()
    
    
class BasicConstraintsRule( CertificateValidationRule ):
    
    def __init__( self , allowCA, pathLength ):
        self._allowCA = allowCA
        self._pathLength = pathLength
        
    def isValid( self, certificate, context ):
        
        passed = False
        caMessage = ''
        pathLengthMessage = ''
        errorMessage = None
        
        extension = certificate.extensions.get_extension_for_oid( x509.oid.ExtensionOID.BASIC_CONSTRAINTS )
        
        if self._allowCA == extension.value.ca:
            passed = True
        else:
            caMessage = 'The "ca" constraint must be {0}.'.format( self._allowCA )
        
        if extension.value.path_length is not None and context.currentPathLength <= extension.value.path_length:
            passed = True
        else:
            pathLengthMessage = 'The pathLength({0}) was exceeded: {1}.'.format( extension.value.path_length, context.currentPathLength )
        
        if not passed:
            errorMessage = caMessage + ' ' + pathLengthMessage
            
        return RuleResult( passed, errorMessage = errorMessage )
    

class ValidityPeriodRule( CertificateValidationRule ):
    
    def isValid( self, certificate, context ):
        
        now = datetime.datetime.now()
        
        valid = now >= certificate.not_valid_before or now < certificate.not_valid_after
        
        if valid:
            return RuleResult( valid )
        else:
            return RuleResult( valid, errorMessage = '{0} is not within {1} - {2}.'.format( now, certificate.not_valid_before, certificate.not_valid_after ) )
    
    
class SignatureHashAlgorithmRule( CertificateValidationRule ):
    
    def __init__( self, hashAlgorithm ):
        self._hashAlgorithm = hashAlgorithm
        
    def isValid( self, certificate, context ):
        valid = self.hashAlgorithmsMatch( certificate.signature_hash_algorithm, self._hashAlgorithm )
    
        if valid:
            return RuleResult( valid )
        else:
            return RuleResult( valid, errorMessage = 'Expected {0}, found {1}.'.format( self._hashAlgorithm, certificate.signature_hash_algorithm ) )
        
    def hashAlgorithmsMatch( self, a, b ):
        return a.block_size == b.block_size and a.digest_size == b.digest_size and a.name == b.name
    

class SignatureVerificationRule( CertificateValidationRule ):
    
    def isValid( self, certificate, context ):
        issuerCertificate = context.chain.findCertificateFor( certificate.issuer  )
        valid = context.delegate.verifySignature( issuerCertificate, certificate )
        if valid:
            return RuleResult( valid )
        else:
            return RuleResult( valid, errorMessage = 'Signature verification failed.' )
        
    
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
            return RuleResult( valid, errorMessage = 'keyUsage({0}) is not equal to allowedUsage({1})'.format( keyUsage, self._allowedUsage ) )
        else:
            return( valid, None )
        
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

        
class CriticalExtensionsRule( CertificateValidationRule ):

    def isValid( self, certificate, context ):
        for extension in certificate.extensions:
            if extension.critical:
                pass
            
        return RuleResult( False, errorMessage = 'Not Implemented!' )
            
 
class SubjectAlternativeNameRule( CertificateValidationRule ):
    '''
    TODO: Enforce standard name content constraints.
    
    @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    '''    
    def isValid( self, certificate, context ):
        if certificate.subject is None:
            # The subject alternate name MUST be present.
            altName = certificate.extensions.get_extension_for_oid( x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME )
            if altName is None:
                return RuleResult( False, errorMessage = 'subjectAltName is required but absent.' )
        return RuleResult( True )
        

class CertificateRevocationListRule( CertificateValidationRule ):
    
    def __init__( self, crlLookup ):
        self._crlLookup = crlLookup
        
    def isValid( self, certificate, context ):
        if self._crlLookup.certificateIsListed( certificate.serial_number ):
            return RuleResult( False, errorMessage = 'Certificate {0} : {1} is revoked.'.format( certificate.subject, certificate.serial_number ) )
        else:
            return RuleResult( True )
                          
            
                                   
