package com.floragunn.searchguard.sgconf;

public class Migration {
    
    //Action groups List (0) format to ES 6 (1) format
    //checker for ES 6 config format to detect unsupported options like composite mode/username implemented in sgadmin
      //or maybe be lenient and just warn and discard
    //SG 7 can load ES 6 config format (do we have any unsupported features then?)
    //migration can only happen after cluster is fully on ES 7˝

}
