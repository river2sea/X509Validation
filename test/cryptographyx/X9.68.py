DomainCertificate {
   iso(1) identified-organization(3) tc68(133) country(16)
      x9(840) x9Standards(9) x9-68(68) modules(0)
         domainCertificate(1) }
   DEFINITIONS AUTOMATIC TAGS ::= BEGIN
-- EXPORTS All;
IMPORTS
   Extensions, UniformResourceIdentifier
      FROM DomainExtensions {
              iso(1) identified-organization(3) tc68(133) country(16)
                 x9(840) x9Standards(9) x9-68(68) modules(0)
                    domainExtensions(2) }
   PublicKeyInfo
      FROM DomainPublicKeys {
              iso(1) identified-organization(3) tc68(133) country(16)
                 x9(840) x9Standards(9) x9-68(68) modules(0)
                    domainPublicKeys(3) }
   Signature
      FROM DomainSignatures {
              iso(1) identified-organization(3) tc68(133) country(16)
                 x9(840) x9Standards(9) x9-68(68) modules(0)
                    domainSignatures(4) };
                    
DomainCertificate ::= SIGNED { EncodedCertificateBody } EncodedCertificateBody ::= ENCODED-TYPE ( CertificateBody ) ENCODED-TYPE ::= TYPE-IDENTIFIER.&Type -- ISO/IEC 8824-2:1998, Annex A
CertificateBody ::= SEQUENCE {
   version             Version  DEFAULT v0,
   signatureAlgorithm  SignatureAlgorithm,
owner
validityPeriod
publicKeyInfo
extensions
privateExtensions   PrivateExtensions  OPTIONAL
Owner,
ValidityPeriod  OPTIONAL,
PublicKeyInfo  OPTIONAL,
Extensions,
ANSI X9-68
© ABA
}
Version ::= INTEGER { v0(0) } ( v0, ... )
SignatureAlgorithm ::= CHOICE {
   signature      RELATIVE-OID,
   x509signature  SignatureAlgorithmId
}
dsaWithSHA-1    RELATIVE-OID ::= { 0 }
ecdsaWithSHA-1  RELATIVE-OID ::= { 1 }
rsaWithSHA-1    RELATIVE-OID ::= { 2 }
dsa RELATIVE-OID ::= { dsaWithSHA-1 0 } -- domain default
ecdsa RELATIVE-OID ::= { ecdsaWithSHA-1 0 } -- domain default -- ecT163k1 RELATIVE-OID ::= { ecdsaWithSHA-1 1 } -- J.4.1(1) -- ecT163r1 RELATIVE-OID ::= { ecdsaWithSHA-1 2 } -- J.4.1(2) -- ecT163r2 RELATIVE-OID ::= { ecdsaWithSHA-1 3 } -- J.4.1(2) -- ecT193r1 RELATIVE-OID ::= { ecdsaWithSHA-1 4 } -- J.4.2(1) -- ecT193r2 RELATIVE-OID ::= { ecdsaWithSHA-1 5 } -- J.4.2(2) -- ecT233k1 RELATIVE-OID ::= { ecdsaWithSHA-1 6 } -- J.4.3(1) -- ecT233r1 RELATIVE-OID ::= { ecdsaWithSHA-1 7 } -- J.4.3(2) -- ecT239k1 RELATIVE-OID ::= { ecdsaWithSHA-1 8 } -- J.4.4(1) -- ecT283k1 RELATIVE-OID ::= { ecdsaWithSHA-1 9 } -- J.4.5(1) -- ecT283r1 RELATIVE-OID ::= { ecdsaWithSHA-1 10 } -- J.4.5(2) -- ecT409k1 RELATIVE-OID ::= { ecdsaWithSHA-1 11 } -- J.4.6(1) -- ecT409r1 RELATIVE-OID ::= { ecdsaWithSHA-1 12 } -- J.4.6(2) -- ecT571k1 RELATIVE-OID ::= { ecdsaWithSHA-1 13 } -- J.4.7(1) -- ecT571r1 RELATIVE-OID ::= { ecdsaWithSHA-1 14 } -- J.4.7(2) -- ecP160k1 RELATIVE-OID ::= { ecdsaWithSHA-1 15 } -- J.5.1(1) -- ecP160r1 RELATIVE-OID ::= { ecdsaWithSHA-1 16 } -- J.5.1(2) -- ecP160r2 RELATIVE-OID ::= { ecdsaWithSHA-1 17 } -- J.5.1(3) -- ecP192k1 RELATIVE-OID ::= { ecdsaWithSHA-1 18 } -- J.5.2(1) -- ecP192r1 RELATIVE-OID ::= { ecdsaWithSHA-1 19 } -- J.5.2(2) -- ecP224k1 RELATIVE-OID ::= { ecdsaWithSHA-1 20 } -- J.5.3(1) -- ecP224r1 RELATIVE-OID ::= { ecdsaWithSHA-1 21 } -- J.5.3(2) -- ecP256k1 RELATIVE-OID ::= { ecdsaWithSHA-1 22 } -- J.5.4(1) -- ecP256r1 RELATIVE-OID ::= { ecdsaWithSHA-1 23 } -- J.5.4(2) -- ecP384r1 RELATIVE-OID ::= { ecdsaWithSHA-1 24 } -- J.5.5(1) -- ecP521r1 RELATIVE-OID ::= { ecdsaWithSHA-1 25 } -- J.5.6(1) --
rsa RELATIVE-OID ::= { rsaWithSHA-1 0 } -- domain default rsa1024 RELATIVE-OID ::= { rsaWithSHA-1 1 }
rsa2048 RELATIVE-OID ::= { rsaWithSHA-1 2 }
rsa3072 RELATIVE-OID ::= { rsaWithSHA-1 3 }
SignatureAlgorithmId ::= AlgorithmIdentifier
SignatureAlgorithms ALGORITHM ::= {
... -- any X9F approved algorithm -- }
Owner ::= SEQUENCE {
   rootName   RootName,
{{ SignatureAlgorithms }}
ANSI X9-68
© ABA
   localName  LocalName  OPTIONAL
}
RootName ::= CHOICE {
   oid            OBJECT IDENTIFIER,
   relative-oid   RELATIVE-OID,
   messageDigest  MessageDigest,
   publicKeyInfo  PublicKeyInfo,
   signature      Signature,
   uri            UniformResourceIdentifier
}
MessageDigest ::= CHOICE {
   digest        OCTET STRING (SIZE(20)) ( ENCODED BY sha-1 ),
   digestedData  DigestedData
}
DigestedData ::= SEQUENCE {
   digestAlgorithm  DigestAlgorithmId,
   digest           OCTET STRING (SIZE(20..MAX))
}
DigestAlgorithmId ::= AlgorithmIdentifier {{ DigestAlgorithms }}
DigestAlgorithms ALGORITHM ::= {
... -- any X9F approved algorithm -- }
LocalName ::= RELATIVE-OID
ValidityPeriod ::= SEQUENCE {
   notBefore  DateTime  OPTIONAL,
   notAfter   DateTime  OPTIONAL
}
(ALL EXCEPT({ -- none; at least one component shall be present -- }))
DateTime ::= RELATIVE-OID -- { yy mm dd hh mm ss z } --
PrivateExtensions ::= SEQUENCE {
   criticality  Criticality  OPTIONAL,
   baseArc      OBJECT IDENTIFIER  OPTIONAL,
   extensions   SEQUENCE SIZE(1..MAX) OF PrivateExtension
}
Criticality ::= BIT STRING (SIZE(1..MAX))
PrivateExtension ::= SEQUENCE {
   name  PRIVATE.&name({ExtensionSet}),
   type  PRIVATE.&Type({ExtensionSet}{@name})  OPTIONAL
}
ExtensionSet PRIVATE ::= { ... -- Defined as needed -- }
PRIVATE ::= CLASS {
   &name  Identifier  UNIQUE,
ANSI X9-68
© ABA
   &Type  OPTIONAL
}
  WITH SYNTAX { NAME &name [TYPE &Type] }
Identifier ::= CHOICE {
oid OBJECT IDENTIFIER, -- complete object identifier
id RELATIVE-OID -- oid fragment relative to baseArc }
-- Object identifiers
sha-1 OBJECT IDENTIFIER ::= {
   iso(1) identified-organization(3) oiw(14) secsig(3)
algorithm(2) sha1(26) } -- From OIW Stable Agreements
      -- Supporting definitions
AlgorithmIdentifier { ALGORITHM:IOSet } ::= SEQUENCE {
   algorithm   ALGORITHM.&id({IOSet}),
   parameters  ALGORITHM.&Type({IOSet}{@algorithm})  OPTIONAL
}
ALGORITHM ::= CLASS {
   &id    OBJECT IDENTIFIER  UNIQUE,
   &Type  OPTIONAL
}
  WITH SYNTAX { OID &id [PARMS &Type] }
SIGNED { ToBeSigned } ::= SEQUENCE {
   toBeSigned ToBeSigned,
   signature  Signature
}
END -- DomainCertificate --


C.1 DomainExtensions ASN.1 Module
DomainExtensions {
   iso(1) identified-organization(3) tc68(133) country(16)
      x9(840) x9Standards(9) x9-68(68) modules(0)
         domainExtensions(2) }
   DEFINITIONS AUTOMATIC TAGS ::= BEGIN
-- EXPORTS All;
IMPORTS
   MessageDigest, ValidityPeriod
      FROM DomainCertificate {
              iso(1) identified-organization(3) tc68(133) country(16)
                 x9(840) x9Standards(9) x9-68(68) modules(0)
                    domainCertificate(1) }
   ORAddress
      FROM MTSAbstractService {
              joint-iso-itu-t mhs(6) mts(3) modules(0)
                 mts-abstract-service(1) version-1999(1) };
Extensions ::= SEQUENCE {
   criticality
Criticality  DEFAULT { keyUsage },
KeyUsage  DEFAULT { digitalSignature },
BasicConstraint  DEFAULT notCA,
PathLenConstraint  OPTIONAL,
keyUsage
basicConstraint
pathLenConstraint
authorityKeyIdentifier    AuthorityKeyIdentifier  OPTIONAL,
KeyIdentifier  OPTIONAL,
ExtKeyUsage  OPTIONAL,
PrivateKeyUsagePeriod  OPTIONAL,
CertificatePolicies  OPTIONAL,
PolicyMappings  OPTIONAL,
GeneralNames  OPTIONAL,
GeneralNames  OPTIONAL,
ownerKeyIdentifier
extKeyUsage
privateKeyUsagePeriod
certificatePolicies
policyMappings
ownerAlternativeName
issuerAlternativeName
ownerDirectoryAttributes  OwnerDirectoryAttributes  OPTIONAL,
nameConstraints policyConstraints externalReference
... -- Expect others --
}
Criticality ::= BIT STRING {
NameConstraints  OPTIONAL,
PolicyConstraints  OPTIONAL,
ExternalReference  OPTIONAL,
ANSI X9-68
© ABA
keyUsage
basicConstraint
pathLenConstraint
authorityKeyIdentifier     (3),
ownerKeyIdentifier         (4),
extKeyUsage                (5),
privateKeyUsagePeriod      (6),
certificatePolicies        (7),
policyMappings             (8),
ownerAlternativeName       (9),
issuerAlternativeName     (10),
ownerDirectoryAttributes  (11),
   nameConstraints
   policyConstraints
   externalReference
} (SIZE(1..15,...))
KeyUsage ::= BIT STRING {
   digitalSignature  (0),
   nonRepudiation    (1),
   keyEncipherment   (2),
   dataEncipherment  (3),
   keyAgreement      (4),
   keyCertSign       (5),
   cRLSign           (6)
(12),
(13),
(14)
} (SIZE(1..7,...))
BasicConstraint ::= BIT STRING { isCA(0) } (SIZE(1))
notCA BasicConstraint ::= '0'B
PathLenConstraint ::= INTEGER (0..MAX)
AuthorityKeyIdentifier ::= SEQUENCE {
   keyIdentifier  KeyIdentifier  OPTIONAL,
   issuer         DirectoryName  OPTIONAL,
   serialNumber   CertificateSerialNumber  OPTIONAL
} --
-- The issuer and serialNumber are paired
-- values and both must be present or absent. --
( WITH COMPONENTS { ...,
      issuer         PRESENT,
      serialNumber   PRESENT } |
  WITH COMPONENTS {
      keyIdentifier  PRESENT,
      issuer         ABSENT,
      serialNumber   ABSENT } )
KeyIdentifier ::= INTEGER (0..MAX)
CertificateSerialNumber ::= INTEGER (0..MAX)
ExtKeyUsage ::= SEQUENCE SIZE(1..MAX) OF KeyPurposeId
(0),
(1),
(2),
ANSI X9-68
© ABA
KeyPurposeId ::= PURPOSE.&id({ KeyPurposes })
KeyPurposes PURPOSE ::= { ... -- Defined as needed -- }
PURPOSE ::= CLASS {
   &id  OBJECT IDENTIFIER  UNIQUE
}
  WITH SYNTAX { PURPOSE &id }
PrivateKeyUsagePeriod ::= ValidityPeriod
CertificatePolicies ::= SEQUENCE SIZE(1..MAX) OF PolicyInformation
PolicyInformation ::= SEQUENCE {
   policyIdentifier  CertPolicyId {{ IssuerPolicies }},
   policyQualifiers  PolicyQualifiers  OPTIONAL
}
CertPolicyId { POLICY:IOSet } ::= POLICY.&id({IOSet})
IssuerPolicies POLICY ::= { ... -- Defined as needed -- }
POLICY ::= CLASS {
   &id  OBJECT IDENTIFIER  UNIQUE
}
  WITH SYNTAX { POLICY &id }
PolicyQualifiers ::= SEQUENCE SIZE(1..MAX) OF PolicyQualifierInfo
PolicyQualifierInfo ::= SEQUENCE {
   id    QUALIFIER.&id({CertPolicyQualifiers}),
   type  QUALIFIER.&Type({CertPolicyQualifiers}{@id})  OPTIONAL
}
CertPolicyQualifiers QUALIFIER ::= { ... -- Defined as needed -- }
QUALIFIER ::= CLASS {
   &id    OBJECT IDENTIFIER  UNIQUE,
   &Type  OPTIONAL
}
 WITH SYNTAX { QUALIFIER-ID &id [QUALIFIER-TYPE &Type] }
PolicyMappings ::= SEQUENCE SIZE(1..MAX) OF SEQUENCE {
   issuerDomainPolicy  CertPolicyId {{ IssuerPolicies }},
   ownerDomainPolicy   CertPolicyId {{ OwnerPolicies }}
}
OwnerPolicies POLICY ::= { ... -- Defined as needed -- }
GeneralNames ::= SEQUENCE SIZE(1..MAX) OF GeneralName
GeneralName ::= CHOICE {
   otherName      OtherName,
   rfc822Name     RFC822Name,
   dNSName        DNSName,
ANSI X9-68
© ABA
}
uri
iPAddress
registeredID
UniformResourceIdentifier,
OCTET STRING,
OBJECT IDENTIFIER
x400Address    ORAddress,
directoryName  DirectoryName,
ediPartyName   EDIPartyName,
OtherName ::= SEQUENCE {
   oid   OTHER-NAME.&id({OtherNames}),
   type  OTHER-NAME.&Type({OtherNames}{@oid})  OPTIONAL
}
OTHER-NAME ::= CLASS {
   &id    OBJECT IDENTIFIER  UNIQUE,
   &Type  OPTIONAL
}
WITH SYNTAX { OID &id [TYPE &Type] }
OtherNames OTHER-NAME ::= { ... -- Defined as needed -- } RFC822Name ::= VisibleString (SIZE(1..MAX))
DNSName ::= VisibleString (SIZE(1..MAX)) (PATTERN "[A-Za-z0-9 .-]+") DirectoryName ::= VisibleString (SIZE(1..MAX)) -- LDAP string format
EDIPartyName ::= SEQUENCE {
   nameAssigner  Party  OPTIONAL,
   partyName     Party
}
Party ::= UTF8String (SIZE(1..MAX))
UniformResourceIdentifier ::=
VisibleString (SIZE(1..MAX)) -- RFC-1630
IPAddress ::= OCTET STRING (SIZE(1..MAX)) OwnerDirectoryAttributes ::= SEQUENCE SIZE(1..MAX) OF Attribute
Attribute ::= SEQUENCE {
   type   ATTRIBUTE.&id({Attributes}),
   value  ATTRIBUTE.&Type({Attributes}{@type})
}
Attributes ATTRIBUTE ::= { ... -- Defined as needed -- }
ATTRIBUTE ::= CLASS {
   &Type,
   &id     OBJECT IDENTIFIER  UNIQUE
}
  WITH SYNTAX { WITH SYNTAX &Type ID &id }
ANSI X9-68
© ABA
NameConstraints ::= SEQUENCE {
   permittedSubtrees  GeneralSubtrees  OPTIONAL,
   excludedSubtrees   GeneralSubtrees  OPTIONAL
}
(ALL EXCEPT({ -- none; at least one component shall be present -- }))
GeneralSubtrees ::= SEQUENCE SIZE(1..MAX) OF GeneralSubtree
GeneralSubtree ::= SEQUENCE {
   base     GeneralName,
   minimum  BaseDistance  DEFAULT 0,
   maximum  BaseDistance  OPTIONAL
}
BaseDistance ::= INTEGER (0..MAX)
PolicyConstraints ::= SEQUENCE {
   requireExplicitPolicy  SkipCerts  OPTIONAL,
   inhibitPolicyMapping   SkipCerts  OPTIONAL
}
(ALL EXCEPT({ -- none; at least one component shall be present -- }))
SkipCerts ::= INTEGER (0..MAX)
ExternalReference ::= SEQUENCE {
   uri     UniformResourceIdentifier,
   digest  MessageDigest
}
END -- DomainExtensions --


D.1 DomainPublicKeysASN.1Module
DomainPublicKeys {
   iso(1) identified-organization(3) tc68(133) country(16) x9(840)
      x9Standards(9) x9-68(68) modules(0)
         domainPublicKeys(3) }
   DEFINITIONS AUTOMATIC TAGS ::= BEGIN
-- EXPORTS All;
IMPORTS
rsaEncryption, RSAPublicKey
   FROM DomainSupport {
           iso(1) identified-organization(3) tc68(133) country(16)
              x9(840) x9Standards(9) x9-68(68) modules(0)
                 domainSupport(5) }
   x962t163k1, x962t163r1, x962t163r2, x962t193r1, x962t193r2,
   x962t233k1, x962t233r1, x962t239k1, x962t283k1, x962t283r1,
   x962t409k1, x962t409r1, x962t571k1, x962t571r1, x962p160k1,
   x962p160r1, x962p160r2, x962p192k1, x962p192r1, x962p224k1,
   x962p224r1, x962p256k1, x962p256r1, x962p384r1, x962p521r1
      FROM ANSI-X9-62 {
              iso(1) member-body(2) us(840) 10045 module(4)
                 ansi-X9-62(1) ver2000(1) };
PublicKeyInfo ::= CHOICE {
dhPublicKey DHPublicKeys, -- X9.42 DH Public Key dsaPublicKey DSAPublicKeys, -- X9.30 DSA Public Key ecPublicKey ECPublicKeys, -- X9.62 EC Public Key rsaPublicKey RSAPublicKeys, -- X9.31 RSA/RW Public Key ... -- Expect others --
}
DHPublicKeys ::= CHOICE {
implicit BIT STRING (CONTAINING DLPublicKey), -- Domain default --
... -- Expect others -- }
DSAPublicKeys ::= CHOICE {
implicit BIT STRING (CONTAINING DLPublicKey), -- Domain default --
... -- Expect others -- }
ANSI X9-68
© ABA
DLPublicKey ::= INTEGER -- Discrete log public key y
ECPublicKeys ::= CHOICE {
   --
-- Named X9.62 elliptic curves
--
implicit BIT STRING (SIZE(176..MAX)), -- Domain default -- ecT163k1 ECPublicKey { x962t163k1, 176, 344 }, -- J.4.1(1) -- ecT163r1 ECPublicKey { x962t163r1, 176, 344 }, -- J.4.1(2) -- ecT163r2 ECPublicKey { x962t163r2, 176, 344 }, -- J.4.1(2) -- ecT193r1 ECPublicKey { x962t193r1, 208, 408 }, -- J.4.2(1) -- ecT193r2 ECPublicKey { x962t193r2, 208, 408 }, -- J.4.2(2) -- ecT233k1 ECPublicKey { x962t233k1, 248, 488 }, -- J.4.3(1) -- ecT233r1 ECPublicKey { x962t233r1, 248, 488 }, -- J.4.3(2) -- ecT239k1 ECPublicKey { x962t239k1, 248, 488 }, -- J.4.4(1) -- ecT283k1 ECPublicKey { x962t283k1, 296, 584 }, -- J.4.5(1) -- ecT283r1 ECPublicKey { x962t283r1, 296, 584 }, -- J.4.5(2) -- ecT409k1 ECPublicKey { x962t409k1, 424, 840 }, -- J.4.6(1) -- ecT409r1 ECPublicKey { x962t409r1, 424, 840 }, -- J.4.6(2) -- ecT571k1 ECPublicKey { x962t571k1, 584, 1160 }, -- J.4.7(1) -- ecT571r1 ECPublicKey { x962t571r1, 584, 1160 }, -- J.4.7(2) -- ecP160k1 ECPublicKey { x962p160k1, 168, 328 }, -- J.5.1(1) -- ecP160r1 ECPublicKey { x962p160r1, 168, 328 }, -- J.5.1(2) -- ecP160r2 ECPublicKey { x962p160r2, 168, 328 }, -- J.5.1(3) -- ecP192k1 ECPublicKey { x962p192k1, 200, 392 }, -- J.5.2(1) -- ecP192r1 ECPublicKey { x962p192r1, 200, 392 }, -- J.5.2(2) -- ecP224k1 ECPublicKey { x962p224k1, 232, 456 }, -- J.5.3(1) -- ecP224r1 ECPublicKey { x962p224r1, 232, 456 }, -- J.5.3(2) -- ecP256k1 ECPublicKey { x962p256k1, 264, 520 }, -- J.5.4(1) -- ecP256r1 ECPublicKey { x962p256r1, 264, 520 }, -- J.5.4(2) -- ecP384r1 ECPublicKey { x962p384r1, 392, 776 }, -- J.5.5(1) -- ecP521r1 ECPublicKey { x962p521r1, 536, 1064 }, -- J.5.6(1) -- ... -- Expect others --
}
ECPublicKey {
   OBJECT IDENTIFIER:ellipticCurve, INTEGER:len1, INTEGER:len2 } ::=
      BIT STRING (SIZE(len1 | len2)) (ENCODED BY ellipticCurve)
-- When an abstract value of ECPoint is used as a public
-- key, and copied into the abstract value in ECPublicKey,
-- the tag and length octets of ECPoint are not included.
ECPoint ::= OCTET STRING
RSAPublicKeys ::= CHOICE {
   --
-- Named RSA public keys
--
implicit BIT STRING (SIZE(1096..MAX)), -- Domain default -- rsa1024 RSA-PublicKey { rsaEncryption, 1096, 2144 }, rsa2048 RSA-PublicKey { rsaEncryption, 2128, 4208 }, rsa3072 RSA-PublicKey { rsaEncryption, 3152, 6256 },
... -- Expect others --
ANSI X9-68
© ABA
}
RSA-PublicKey {
   OBJECT IDENTIFIER:keyType, INTEGER:len1, INTEGER:len2 } ::=
      BIT STRING (SIZE(len1..len2))
         (CONTAINING RSAPublicKey ENCODED BY keyType)
-- When an abstract value of RSAPublicKey is used as a public
-- key, and copied into the abstract value in RSA-PublicKey,
-- all of the tag and length octets of a DER encoded value of
-- type RSA-PublicKey are included.
END -- DomainPublicKeys --



DomainSignatures {
   iso(1) identified-organization(3) tc68(133) country(16)
      x9(840) x9Standards(9) x9-68(68) modules(0)
         domainSignatures(4) }
   DEFINITIONS AUTOMATIC TAGS ::= BEGIN
-- EXPORTS All;
IMPORTS
   SignatureAlgorithmId
      FROM DomainCertificate {
              iso(1) identified-organization(3) tc68(133) country(16)
                 x9(840) x9Standards(9) x9-68(68) modules(0)
                    domainCertificate(1) }
   ECDSA-Sig-Val, rsaEncryption
      FROM DomainSupport {
              iso(1) identified-organization(3) tc68(133) country(16)
                 x9(840) x9Standards(9) x9-68(68) modules(0)
                    domainSupport(5) }
   x962t163k1, x962t163r1, x962t163r2, x962t193r1, x962t193r2,
   x962t233k1, x962t233r1, x962t239k1, x962t283k1, x962t283r1,
   x962t409k1, x962t409r1, x962t571k1, x962t571r1, x962p160k1,
   x962p160r1, x962p160r2, x962p192k1, x962p192r1, x962p224k1,
   x962p224r1, x962p256k1, x962p256r1, x962p384r1, x962p521r1
      FROM ANSI-X9-62 {
              iso(1) member-body(2) us(840) 10045 module(4)
                 ansi-X9-62(1) ver2000(1) };
Signature ::= CHOICE {
   domainSignature  DomainSignature,
   x509signature    X509Signature
}
X509Signature ::= SEQUENCE {
   x509signature  SignatureAlgorithmId,
   signature      BIT STRING
}
DomainSignature ::= CHOICE {
ANSI X9-68 © ABA
dsaSignature DSASignatures, -- X9.30 DSA Signature ecdsaSignature ECDSASignatures, -- X9.62 ECDSA Signature rsaSignature RSASignatures, -- X9.31 RSA/RW Signature ... -- Expect others --
}
DSASignatures ::= CHOICE {
implicit BIT STRING (CONTAINING DSA-Sig-Val), -- Domain default --
... -- Expect others -- }
DSA-Sig-Val ::= ECDSA-Sig-Val
ECDSASignatures ::= CHOICE {
   --
-- Named X9.62 elliptic curves
--
implicit BIT STRING (SIZE(64..MAX)), -- Default domain curve -- ecT163k1 ECDSASignature { x962t163k1, 384 }, -- J.4.1 example 1 ecT163r1 ECDSASignature { x962t163r1, 384 }, -- J.4.1 example 2 ecT163r2 ECDSASignature { x962t163r2, 384 }, -- J.4.1 example 3 ecT193r1 ECDSASignature { x962t193r1, 448 }, -- J.4.2 example 1 ecT193r2 ECDSASignature { x962t193r2, 448 }, -- J.4.2 example 2 ecT233k1 ECDSASignature { x962t233k1, 528 }, -- J.4.3 example 1 ecT233r1 ECDSASignature { x962t233r1, 528 }, -- J.4.3 example 2 ecT239k1 ECDSASignature { x962t239k1, 528 }, -- J.4.4 example 1 ecT283k1 ECDSASignature { x962t283k1, 624 }, -- J.4.5 example 1 ecT283r1 ECDSASignature { x962t283r1, 624 }, -- J.4.5 example 2 ecT409k1 ECDSASignature { x962t409k1, 864 }, -- J.4.6 example 1 ecT409r1 ECDSASignature { x962t409r1, 880 }, -- J.4.6 example 2 ecT571k1 ECDSASignature { x962t571k1, 1200 }, -- J.4.7 example 1 ecT571r1 ECDSASignature { x962t571r1, 1200 }, -- J.4.7 example 2 ecP160k1 ECDSASignature { x962p160k1, 384 }, -- J.5.1 example 1 ecP160r1 ECDSASignature { x962p160r1, 384 }, -- J.5.1 example 2 ecP160r2 ECDSASignature { x962p160r2, 384 }, -- J.5.1 example 3 ecP192k1 ECDSASignature { x962p192k1, 448 }, -- J.5.2 example 1 ecP192r1 ECDSASignature { x962p192r1, 448 }, -- J.5.2 example 2 ecP224k1 ECDSASignature { x962p224k1, 512 }, -- J.5.3 example 1 ecP224r1 ECDSASignature { x962p224r1, 512 }, -- J.5.3 example 2 ecP256k1 ECDSASignature { x962p256k1, 576 }, -- J.5.4 example 1 ecP256r1 ECDSASignature { x962p256r1, 576 }, -- J.5.4 example 2 ecP384r1 ECDSASignature { x962p384r1, 832 }, -- J.5.5 example 1 ecP521r1 ECDSASignature { x962p521r1, 1104 }, -- J.5.6 example 1 ... -- Expect others --
}
ECDSASignature { OBJECT IDENTIFIER:ellipticCurve, INTEGER:length } ::=
   BIT STRING (SIZE(64..length))
      (CONTAINING ECDSA-Sig-Val ENCODED BY ellipticCurve)
RSASignatures ::= CHOICE {
implicit BIT STRING (SIZE(1024..MAX)), -- Domain default -- rsa1024 RSA-Signature { rsaEncryption, 1024 }, -- 128 octets -- rsa2048 RSA-Signature { rsaEncryption, 2048 }, -- 256 octets -- rsa3072 RSA-Signature { rsaEncryption, 3072 }, -- 384 octets --
ANSI X9-68
© ABA
... -- Expect others -- }
RSA-Signature { OBJECT IDENTIFIER:signatureType, INTEGER:length } ::=
   BIT STRING (SIZE(length)) (ENCODED BY signatureType)
END -- DomainSignatures --




DomainSupport {
   iso(1) identified-organization(3) tc68(133) country(16)
      x9(840) x9Standards(9) x9-68(68) modules(0)
         domainSupport(5) }
   DEFINITIONS IMPLICIT TAGS ::= BEGIN
-- EXPORTS All; --
-- IMPORTS None; --
ECDSA-Sig-Val ::= SEQUENCE {
   r  INTEGER,
s INTEGER }
RSAPublicKey ::= SEQUENCE {
modulus INTEGER, -- n=pq publicExponent INTEGER -- e
}
rsaEncryption OBJECT IDENTIFIER ::= {
   iso(1) member-body(2) us(840) rsadsi(113549)
      pkcs(1) pkcs-1(1) rsaEncryption(1)
}
END -- DomainSupport --



