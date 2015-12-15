#!/usr/bin/python

import sys
import unittest

sys.path.extend( [ "src", "test" ] )
                  
import x509Validation.ValidationTest


if __name__ == '__main__':
    
    succeeded = True

    modules = [ 
        x509Validation.ValidationTest
    ]
    
    for module in modules:
        suite = unittest.loader.findTestCases( module )
        runner = unittest.TextTestRunner()
        result = runner.run( suite )    
        print( "Result:", result )
        if len( result.errors ) > 0 or len( result.failures ) > 0 :
            succeeded = False
        
    if succeeded:
        sys.exit( 0 )
    else:
        sys.exit( 1 )