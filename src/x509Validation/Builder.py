import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from x509Validation.ValidationTest import trustedKeyUsage, untrustedKeyUsage


class Builder( object ):
    
    def __init__( self, hashAlgorithm, backend = default_backend ):
        self.hashAlgorithm = hashAlgorithm
        self.backend = backend
        
    def generateCACertificate( self, issuerName, subjectName, validityDays, publicKey, privateKey ):
        '''
        Generate a self-signed certificate capable of signing, verification, ...
        @return: a DER|PEM encoded X509v3 certificate.
        '''
        builder = x509.CertificateBuilder()
        builder = builder.subject_name( x509.Name( subjectName ) )
        builder = builder.issuer_name( x509.Name( issuerName ) ) 
        today = datetime.datetime.today()
        builder = builder.not_valid_before( today )
        endDate = today + datetime.timedelta( days = validityDays )
        builder = builder.not_valid_after( endDate )
        builder = builder.serial_number( int( uuid.uuid4() ) )
        builder = builder.public_key( publicKey )
        # The path length is 0 - ie this certificate cannot create subordinate signing-certificates.
        builder = builder.add_extension( x509.BasicConstraints( ca = True, path_length = 0 ), critical = True )
        builder = builder.add_extension( trustedKeyUsage, critical = True )
        digest = x509.SubjectKeyIdentifier.from_public_key( publicKey )
        builder = builder.add_extension( digest, critical = True )
        certificate = builder.sign( private_key = privateKey, algorithm = self.hashAlgorithm, backend = self.backend )    
        return certificate
    
    def generateUserCertificate( self, issuerName, subjectName, validityDays, publicKey, privateKey ):
        '''
        Generate a certificate signed by a CA or intermediate-CA certificate.
        Do not allow signing. Allow verification, ...
        @return: a DER|PEM encoded X509v3 certificate.
        '''
        builder = x509.CertificateBuilder()
        builder = builder.subject_name( x509.Name( subjectName ) )
        builder = builder.issuer_name( x509.Name( issuerName ) ) 
        today = datetime.datetime.today()
        builder = builder.not_valid_before( today )
        endDate = today + datetime.timedelta( days = validityDays )
        builder = builder.not_valid_after( endDate )
        builder = builder.serial_number( int( uuid.uuid4() ) )
        builder = builder.public_key( publicKey )        
        # The path length is 0 - ie this certificate cannot create subordinate signing-certificates.        
        builder = builder.add_extension( x509.BasicConstraints( ca = False, path_length = None ), critical = True )
        builder = builder.add_extension( untrustedKeyUsage, critical = True )
        subjectKeyIdentifier = x509.SubjectKeyIdentifier.from_public_key( publicKey )
        builder = builder.add_extension( subjectKeyIdentifier, critical = True )
        certificate = builder.sign( private_key = privateKey, algorithm = self.hashAlgorithm, backend = self.backend )    
        return certificate
    
