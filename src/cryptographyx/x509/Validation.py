'''
@author: Rowland Smith : rowland@river2sea.org
@license: MIT

@see https://en.wikipedia.org/wiki/X.509
@see https://en.wikipedia.org/wiki/Certification_path_validation_algorithm

'''

from abc import ABCMeta, abstractmethod
import datetime
import logging

from cryptography import x509


class CertificateChainContext( object ):
    '''
    Provides a mutable context for the recursive CertificateChain.isValid()
    method that validates a certificate chain.
    '''
    
    def __init__( self ):  
        self.currentCertificate = None
        self.currentPathLength = 0
        self.failEarly = False
        self.failNow = False
        self.delegate = None
        self._log = None
        
    def ruleFailed( self, rule ):
        '''
        The default implementation is a no-op. See ErrorCollectingCertificateChainContext
        for a context that can collect errors as they are detected and provides
        a property 'errors' to retrieve all errors after path validation finishes running.
        '''
        pass
    
    @property
    def log( self ):
        if self._log is None:
            self._log = logging.getLogger( 'cryptographyx.x509' )
        return self._log
    
    @log.setter
    def log( self, value ):
        self._log = value 
        
            
class ErrorCollectingCertificateChainContext( CertificateChainContext ):
    '''
    A concrete CertificateChainContext context that can collect errors as 
    they are detected and provides a property 'errors', to retrieve all 
    errors after path validation finishes running.
    '''    
    def __init__( self ):  
        CertificateChainContext.__init__( self )
        self.currentCertificate = None
        self.currentPathLength = 0
        self.errors = []
        
    def ruleFailed( self, rule, result ):
        self.errors.append( ( rule, result ) )
        
    def __str__( self ):
        return 'ErrorCollectingCertificateChainContext errors=' + str( self.errors )
    
        
class CertificateChain( object ):
    '''
    Configure with trusted certificates and a rule set for trusted certificates
    and untrusted certificates, then validate an untrusted certificate against
    the trusted certificates and the rule sets.
    
    @param trustedCertificates a TrustedCertificateLookup that returns 
                               cryptography.hazmat.x509.Certificate objects
                               based on issuer name.
    
    @parm trustedRules a CompositeValidationRule (typically) that contains
                       an ordered list of CertificateValidationRule(s) that
                       are applied to each trusted certificate in the chain.
                       
    @parm untrustedRules a CompositeValidationRule (typically) that contains
                       an ordered list of CertificateValidationRule(s) that
                       are applied to each untrusted certificate in the chain.        
    '''
    def __init__( self, delegate, trustedCertificates, trustedRules, untrustedRules ):
        self._delegate = delegate
        self._trustedCertificates = trustedCertificates
        self._trustedLookup = trustedCertificates
        self._trustedRules = trustedRules
        self._untrustedRules = untrustedRules
        self._currentPathLength = 0
        self._context = CertificateChainContext()
        self._log = None
        
    @property
    def log( self ):
        '''
        The logger to use for error logging, etc.
        '''
        if self._log is None:
            self._log = logging.getLogger( 'cryptographyx.x509' )
        return self._log
    
    @log.setter
    def log( self, value ):
        self._log = value 
        
    def isValid( self, certificate, context ):
        
        rules = None
        
        if context.currentCertificate == None:
            # This is the untrusted certificate that begins the chain.
            context.currentCertificate = certificate
            rules = self._untrustedRules
        else:
            rules = self._trustedRules
                    
        result = rules.isValid( certificate, context )
        
        if result.isValid:
            if certificate.subject == certificate.issuer :
                # We found a root.
                return True
            else:
                issuerCertificate = self._trustedLookup.findCertificateFor( certificate.issuer )
                context.currentCertificate = issuerCertificate
                return self.isValid( issuerCertificate, context )            
        else:
            return False
            

class CertificateChainDelegate( metaclass = ABCMeta ):
    
    @abstractmethod
    def verifySignature( self, issuerCertificate, signatureAlgorithm, toBeSigned ):
        '''
        Return true if the signature is valid for the given data.
        '''
        pass
    
    
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
    
    If CertificateChainContext.failEarly is True, then this
    collection of rules will raise a CertificateException on
    the first rule that fails.
    
    If False, all rules will be executed and failures will
    be passed to CertificateChainContext.ruleFailed().
    
    ErrorCollectingCertificateChainContext will collect all
    failures in ErrorCollectingCertificateChainContext.errors.
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
            
            # try:
            result = rule.isValid( certificate, context )
            # except Exception as e:
            # context.log.error( sys.exc_info()  ) # TODO: capture stack trace, log with logging...
                
            if not result.isValid:
                context.ruleFailed( rule, result )
                if context.failEarly:
                    context.failNow = True
                
        return RuleResult( True )
    
      
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
        signatureAlgorithm = None
        toBeSigned = None
        valid = context.delegate.verifySignature( certificate, signatureAlgorithm, toBeSigned )

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
        
 
class CertificateRevocationListLookup( metaclass = ABCMeta ):
    
    @abstractmethod
    def certificateIsListed( self, serialNumber ):
        pass
    
    
class CertificateRevocationListRule( CertificateValidationRule ):
    
    def __init__( self, crlLookup ):
        self._crlLookup = crlLookup
        
    def isValid( self, certificate, context ):
        if self._crlLookup.certificateIsListed( certificate.serial_number ):
            return RuleResult( False, errorMessage = 'Certificate {0} : {1} is revoked.'.format( certificate.subject, certificate.serial_number ) )
        else:
            return RuleResult( True )
                          
                          
class TrustedCertificateLookup( metaclass = ABCMeta ):
    
    @abstractmethod
    def findCertificateFor( self, issuer ):
        pass
       
      
class ListBackedCertificateLookup( TrustedCertificateLookup ):
    '''
    TODO: What is the correct behavior if two or more certificates
    are found with the same subject name? -rds
    '''
    def __init__( self, rootCertificateList ):
        self._roots = rootCertificateList
        
    def findCertificateFor( self, subject ):
        for certificate in self._roots:
            # Is this doing a value comparison? -rds
            if certificate.subject == subject:
                return certificate
    
        
