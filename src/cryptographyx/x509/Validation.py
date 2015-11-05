'''
@author: Rowland Smith : rowland@river2sea.org
@license: MIT

@see https://en.wikipedia.org/wiki/X.509
@see https://en.wikipedia.org/wiki/Certification_path_validation_algorithm
@see http://tools.ietf.org/html/rfc4158
'''

from abc import ABCMeta, abstractmethod
import contextlib
import glob
import logging
import os

from cryptography import x509
from cryptography.hazmat import backends
from cryptographyx.x509.Rule import RuleResult


class PathValidationContext( object ):
    '''
    Provides a mutable context for the recursive CertificateChain.isValid()
    method that validates a certificate chain.
    '''
    
    def __init__( self, chain ):  
        self._chain = chain
        self.currentCertificate = None
        self.currentPathLength = 0
        self.failEarly = False
        self.failNow = False
        self.failed = False
        self.delegate = None
        self._log = None
        
    @property
    def chain( self ):
        return self._chain
    
    @property
    def log( self ):
        if self._log is None:
            self._log = logging.getLogger( 'cryptographyx.x509' )
        return self._log
    
    @log.setter
    def log( self, value ):
        self._log = value 
        
        
class CertificateChainDelegate( metaclass = ABCMeta ):
    
    @abstractmethod
    def currentTime( self ):
        '''
        Return the datetime.datetime that should be used to 
        check a certificate's validity period.
        @return: a datetime.datetime object.
        '''
        pass
    
    @abstractmethod
    def verifySignature( self, issuerCertificate, subjectCertificate ):
        '''
        Return true if the subjectCertificate was signed with the issuerCertificate's private-key.
        '''
        pass
    
    @abstractmethod
    def ruleFailed( self, ruleResult ):
        '''
        Called when a CertificateValidationRule fails.
        '''
        pass
    
    @abstractmethod
    def shouldFailEarly( self ):
        '''
        Return True if path validation should abort when the first
        rule fails, or if it should continue processing the certificate
        so we can gather all of the errors in the certificate when it
        contains more than one defect.
        '''
        pass
    
            
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
        
    def isValid( self, certificate ):
        context = PathValidationContext( self )
        context.delegate = self._delegate
        self._validate( certificate, context )
        return not context.failed
        
    def _validate( self, certificate, context ):
        
        if context.failed and context.failNow:
            return False
        
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
                # TODO: Make issuer lookup a Rule.
                if issuerCertificate is None:
                    context.delegate.ruleFailed( RuleResult( False, errorMessage = "The issuer certificate was not found: {0}".format( certificate.issuer ) ) )
                    context.failed = True
                    return False
                context.currentCertificate = issuerCertificate
                context.currentPathLength = context.currentPathLength + 1
                return self._validate( issuerCertificate, context )            
        else:
            context.failed = True
            return False
            
    def findCertificateFor( self, subjectName ):
        '''
        Exposes the _trustedCertificates lookup for use by rules.
        '''
        return self._trustedCertificates.findCertificateFor( subjectName )
    

class CertificateRevocationListLookup( metaclass = ABCMeta ):
    
    @abstractmethod
    def certificateIsListed( self, serialNumber ):
        pass
    
                    
class TrustedCertificateLookup( metaclass = ABCMeta ):
    
    @abstractmethod
    def findCertificateFor( self, issuer ):
        pass
       
      
class ListBackedCertificateLookup( TrustedCertificateLookup ):
    '''
    Looks up trusted certificates by subject name. The search
    is iterative and the list of certificates can contain
    multiple validation paths.
    
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
  
    
class DirectoryBackedCertificateLookup( TrustedCertificateLookup ):
    '''
    Searches a list of Certificates loaded from a directory on disk.
    The encoding format of the certificates is assumed to be DER.
    '''
    def __init__( self, directoryPath, fileExtension = '.der' ):
        self._directoryPath
        self._fileExtension = fileExtension
        self._trustedCertificates = None
        
    def findCertificateFor( self, subject ):        
        # Defer loading the Certificates from disk until they are requested.
        #
        if self._trustedCertificates is None:
            
            self._trustedCertificates = []
            paths = glob.glob( os.path.join( self._directoryPath, '*.{0}'.format( self._fileExtension ) ) )
            
            for path in paths:
                with open( path, 'rb' ) as inputFile:
                    data = inputFile.read()
                
                if self._fileExtension == '.der':
                    certificate = x509.load_der_x509_certificate( data, backends.default_backend() )
                elif self._fileExtension == '.pem':
                    certificate = x509.load_pem_x509_certificate( data, backends.default_backend() )
                else:
                    logging.ERROR( 'Unsupported Certificate file extension: {0}.'.format( self._fileExtension ) )
                    # logging.WARNING( 'The file {0} does not have the specified extension: {1}.'.format( path, self._fileExtension ) )
                    
                self._trustedCertificates.append( certificate )
      
        for certificate in self._trustedCertificates:
            # Is this doing a value comparison? -rds
            if certificate.subject == subject:
                return certificate


class SingleOrderedPathCertificateLookup( TrustedCertificateLookup ):
    '''
    The certificates passed to the constructor must already be in
    the correct lookup order where:
    
        trustedCertificates[ 0 ] is signed by trustedCertificates[ 1 ] is signed by trustedCertificates[ 2 ] ...
        
    The 'trustedCertificateList' certificate path will be pre-validated
    so that we may use a fast dictionary lookup based on certificate.subject
    in the findCertificateFor(...) method.
    '''
    
    def __init__( self, trustedCertificateList ):
        self._trustedCertificates = {}
        self._preValidate( trustedCertificateList )
        for certificate in trustedCertificateList:
            self._trustedCertificates[ certificate.subject ] = certificate
        
    def findCertificateFor( self, subject ):
        return self._trustedCertificates[ subject ]
    
    def _preValidate( self, trustedCertificateList ):
        raise( ValueError( 'Invalid trusted certificate chain.' ) )
    
    
    
