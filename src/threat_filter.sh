#!/bin/sh

# *************************************************************************
# Copyright 2019 Global Cyber Aliance
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *************************************************************************

# Sample Input line:
#     9.9.9.9.53 > 192.168.1.163.28423: [udp sum ok] 55783 NXDomain- q: A? mewsxzsa27.club. 0/0/0 (33)
#
# Where in AWK:
#      $11 = FQDN in question
#      $10 = DNS operation: (  "A?"    = IPV4 DNS Request
#                              "AAAA?" = IPV6 DNS Request
#                              "SOA?"  = 
#                              "PTR?"  =

DNSEVENTFILE="/var/log/dhcp_q9thrt_log.txt"
MUD_FILE_DIRECTORY="/etc/q9thrt/state/mudfiles"
Q9_RULE_STATE_DIRECTORY="/etc/q9thrt/state/rules"
Q9_LOG_FILE="q9thrt.log"
Q9_ERR_FILE="q9thrt.err"
Q9_AUDIT_FILE="q9thrt_audit.log"
Q9_FAIL_FILE="q9thrt_event_failure.log"
Q9_LOG_DIR="/etc/q9thrt/logs"
Q9_ARCHIVE_DIR="/etc/q9thrt/logArchive"
Q9_TMP_DIR="/tmp/q9thrt_tmp_dir"
DEBUG_MODE=0

usage() { 
  echo "Usage: 
Required: -e $<DHCP_EVENT_FILE> -m <MUD_FILE_DIRECTORY> -l <Q9_LOG_FILE> -a <Q9_AUDIT_FILE> -f <Q9_FAIL_FILE> -g <Q9_ARCHIVE_DIR> -o <Q9_LOG_DIR> -s <Q9_RULE_STATE_DIRECTORY> -t <Q9_TMP_DIR>
Optional: -d [DEBUG MODE]" 1>&2; 
  exit 0; 
}

while getopts 'e:m:l:a:f:g:o:s:t:hd' option; do
    case "${option}" in
        d) DEBUG_MODE=1;;
        e) DNSEVENTFILE=$OPTARG;;
        m) MUD_FILE_DIRECTORY=$OPTARG;;
        l) Q9_LOG_FILE=$OPTARG;;
        a) Q9_AUDIT_FILE=$OPTARG;;
        f) Q9_FAIL_FILE=$OPTARG;;
        g) Q9_ARCHIVE_DIR=$OPTARG;;
        o) Q9_LOG_DIR=$OPTARG;;
        s) Q9_RULE_STATE_DIRECTORY=$OPTARG;;
        t) Q9_TMP_DIR=$OPTARG;;
        h | *) usage;;
    esac
done

if [[ -z "${DNSEVENTFILE/ //}" ]]; then
    echo -e "ERROR: Please specify the DNSEVENTFILE log file [ -e <file> ]!\n"
    exit 1
fi

if [[ -z "${MUD_FILE_DIRECTORY/ //}" ]]; then
    echo -e "ERROR: Please specify the MUD_FILE_DIRECTORY log file [ -m <directory> ]!\n"
    exit 1
fi

if [[ -z "${Q9_RULE_STATE_DIRECTORY/ //}" ]]; then
    echo -e "ERROR: Please specify the Q9_RULE_STATE_DIRECTORY log file [ -s <directory> ]!\n"
    exit 1
fi

echo "Running Quad9 Threat Signalling using the startup configuration:"
echo "    DNS-EVENT-FILE: ${DNSEVENTFILE}"
echo "    Mud File Directory: ${MUD_FILE_DIRECTORY}"
echo "    Rule State Directory: ${Q9_RULE_STATE_DIRECTORY}"
echo "    Quad9 Tmp Directory: ${Q9_TMP_DIR}"
echo "    Quad9 Log Directory: ${Q9_LOG_DIR}"
echo "    Debug Mode: ${DEBUG_MODE}"
echo " "

#
# Run main AWK program for scanning the DNS events
#
# cat ${DNSEVENTFILE} | awk -v MUD_FILE_DIRECTORY="$MUD_FILE_DIRECTORY" -v Q9_RULE_STATE_DIRECTORY="$Q9_RULE_STATE_DIRECTORY" '
# tail -F ${DNSEVENTFILE} | awk -v MUD_FILE_DIRECTORY="$MUD_FILE_DIRECTORY" -v Q9_RULE_STATE_DIRECTORY="$Q9_RULE_STATE_DIRECTORY" -v Q9_TMP_DIR="$Q9_TMP_DIR" '

tcpdump --immediate-mode -n -i eth1 -vv port 53 | tee ${DNSEVENTFILE} | awk -v MUD_FILE_DIRECTORY="$MUD_FILE_DIRECTORY" -v Q9_RULE_STATE_DIRECTORY="$Q9_RULE_STATE_DIRECTORY" -v Q9_TMP_DIR="$Q9_TMP_DIR" -v DEBUG_MODE="$DEBUG_MODE" '

# If any of these found, trim string at that char and log WARN message
# Patterns:
#  ;
#  &&      
#  |    
#  ...
function sanitizeInput(inputStr) {
    locPos = 0;
    newStr = "";

    if (inputStr != "") {
        locPos = index(inputStr, ";");
        if (locPos != 0) {
            newStr = substr(inputStr, 0, locPos-1);
            print "WARN: sanitizeInput(): Found possible command injection (;) : fixed to: " newStr;
        } else {
            locPos = index(inputStr, "&");
            if (locPos != 0) {
                newStr = substr(inputStr, 0, locPos-1);
                print "WARN: sanitizeInput(): Found possible command injection (&&) : fixed to: " newStr;
            } else {
                locPos = index(inputStr, "|");
                if (locPos != 0) {
                    newStr = substr(inputStr, 0, locPos-1);
                    print "WARN: sanitizeInput(): Found possible command injection (|) : fixed to: " newStr;
                } else {
                    locPos = index(inputStr, "..");
                    if (locPos != 0) {
                        newStr = substr(inputStr, 0, locPos-1);
                        print "WARN: sanitizeInput(): Found possible command injection (...) : fixed to: " newStr;
                    } else {
                        newStr = inputStr;
                    }
                }
            }
        }
    } else {
        print "WARN: sanitizeInput(): Ignoring empty FQDN";
    }
    return newStr;
}


function isQuad9Blocked(fqdnInfoFile) {
    THREAT_BLOCKED = "false";

    threatCommand = JQCMD " .blocked " fqdnInfoFile
    print "DEBUG: isQuad9Blocked(): Calling: " threatCommand; 

    threatCommand | getline QTHREAT_RESULT;

    print "DEBUG: isQuad9Blocked(): Command result: " QTHREAT_RESULT;
    
    if (QTHREAT_RESULT == "true") {
        THREAT_BLOCKED = "true";
    } else {
        print "DEBUG: isQuad9Blocked(): Threat not found by Quad9.";
    }

    return THREAT_BLOCKED;
}

function isBlockedByProvider(fqdnInfoFile, threatIntelProvider) {
    PROVIDER_AWARE = "false";

    threatCommand = JQCMD " -c .blocked_by " fqdnInfoFile
    print "DEBUG: isBlockedByProvider(): Calling: " threatCommand; 

    threatCommand | getline PTHREAT_RESULT;

    print "DEUBG: isBlockedByProvider(): " PTHREAT_RESULT " ---===--- " threatIntelProvider;

    if (index(PTHREAT_RESULT, threatIntelProvider) != 0) {
        print "WARN: isBlockedByProvider(): Threat WAS FOUND TO BE BAD by " threatIntelProvider;
        PROVIDER_AWARE = "true";
    } else {
        print "INFO: isBlockedByProvider(): Threat not found by provider " threatIntelProvider;
    }

    return PROVIDER_AWARE;
}

function testMudFile(localFile) {
    VALID_MUD_FILE = "false";
    mudVersion = "";
    
    testMudFile = JQCMD " -r '\''.[\"ietf-mud:mud\"][\"mud-version\"]'\'' " localFile
    print "DEBUG: testMudFile(): Calling: " testMudFile; 

    testMudFile | getline mudVersion;
    
    if (mudVersion == "1") {
        print "DEBUG: testMudFile(): Valid Mud file: MudVersion = " mudVersion;
        VALID_MUD_FILE = "true";
    } else {
        print "ERROR: testMudFile(): An invalid MUD file was download from the threat provider.";
    }

    return VALID_MUD_FILE;    
}

function testMudFileSignature(localFile) {
    VALID_MUD_SIG_FILE = "false";
    sigOutput = "";
    
    testP7sCommand = "openssl asn1parse -in " localFile " -inform der | grep -i error | wc -l";
    print "DEBUG: testMudFileSignature(): Calling: " testP7sCommand; 

    testP7sCommand | getline sigOutput;
    
    if (sigOutput == "0") {
        print "DEBUG: testMudFileSignature(): Valid Mud file signature.";
        VALID_MUD_SIG_FILE = "true";
    } else {
        print "ERROR: testMudFileSignature(): An invalid MUD file signature was download from the threat provider.";
    }

    return VALID_MUD_SIG_FILE;    
}

#
# retrieveThreatProviderFile(): Will retrieve a MUD or MUD signature file from a threat provider.
#      A "json" exension indicates the file is a MUD file and a test for "ietf-mud:mud" indicates a valid MUD file
#             CMD: jq -r '.["ietf-mud:mud"]["mud-version"]' <threat>.json
#      A "p7s" extension indicates a DER formatted SMIME digital signature file. Verify searching for "Error in encoding" in output:
#             CMD: openssl asn1parse -in <fqdn>.p7s -inform der | grep -i error | wc -l
#
#      Based on the filetype, true or false will be returned indicating a valid file
#
function retrieveThreatProviderFile(fqdn, localFile, extension) {
    VALID_FILE = "false";
    finalUrl = CURLCMD " -o " localFile " " THREATHOST "/" fqdn "." extension;
    print "DEBUG: retrieveThreatProviderFile(): Calling: " finalUrl; 
    
    rc = system ( finalUrl );
    if (rc == 0) {
        print "INFO: retrieveThreatProviderFile(): MUD FILE RETRIEVED";
        VALID_FILE = "true";
    } else {
        print "ERROR: retrieveThreatProviderFile(): No mud file <-----------. RC=" rc ".";
    }
    
    return VALID_FILE;
}

function validateThreatMudFile(threatMudFile, threatP7sFile) {
    validSig = "false";
    validSigFile = "false";
    validMudFile = "false";
    
    validMudFile = testMudFile(threatMudFile);
    validSigFile = testMudFileSignature(threatP7sFile);
    if ((validMudFile == "true") && (validSigFile == "true")) {
        print "DEBUG: validateThreatMudFile(): Both the MUD file and MUD p7s signature files are valid. Now test signature."
        
        finalCmd = "openssl cms -verify -in " threatP7sFile " -inform DER -content " threatMudFile " > /dev/null";
        print "DEBUG: validateThreatMudFile(): Calling: " finalCmd; 
        
        rc = system ( finalCmd );
        if (rc == 0) {
            print "INFO: validateThreatMudFile(): MUD FILE SIGNATURE PASSED";
            validSig = "true";
        } else {
            print "ERROR: validateThreatMudFile(): Could Not validate mud file usind associated p7s signature file.<-----------";

            if (DEBUG_MODE == 1) {
                print "DEBUG MODE: Continue processing VALID MUD file with bad signature in DEBUG model";
                validSig = "true"        
            }
        }
    
    } else {
        print "ERROR: validateThreatMudFile(): Something wrong with MUD files: Valid MUD file: " validMudFile ". Valid Signature file: " validSigFile;
        
        if ((validMudFile == "true") && (DEBUG_MODE == 1)) {
             print "DEBUG MODE: Continue processing VALID MUD file with bad signature in DEBUG model";
             validSig = "true"        
        }
    }

    return validSig;
}

function installMudFile(threatMudFile, fqdn, src, dst) {
    retval = "success";
    finalCmd = MUD_PROCESSOR_CMD " -e " fqdn " -m " threatMudFile " -s " src " -d " dst " -k " Q9_RULE_STATE_DIRECTORY;
    print "DEBUG: installMudFile(): Calling: " finalCmd; 

    rc = system ( finalCmd );
    if (rc == 0) {
        print "INFO: installMudFile(): MUD FILE INSTALLED";
    } else {
        retval = "failure";
        print "ERROR: installMudFile(): Failed installing mud file<-----------";
    }
    
    return retval;
}

function commitThreatConfiguration() {
    retval = "success";
    finalcmd = COMMIT_CONFIG_CMD " -d " Q9_RULE_STATE_DIRECTORY " -t " Q9_TMP_DIR  ;
    print "DEBUG: commitThreatConfiguration(): Calling: " finalcmd; 

    rc = system ( finalcmd );
    if (rc == 0) {
        print "INFO: commitThreatConfiguration(): OpenWRT Config INSTALLED";
    } else {
        retval = "failure";
        print "ERROR: commitThreatConfiguration(): Failed installing of OpenWRT configuration<-----------";
    }
    
    return retval;
}


function buildFilename(directory, fqdn, extension) {
    THREATTMPFILE = directory "/" fqdn extension;

    return THREATTMPFILE;
}

function runQuad9(theFqdn) {
     threatValue = "";
     threatTest = "false";
     validSig = "false";
     validFile = "false";
     threatTmpFile = buildFilename("/tmp", theFqdn, ".q9");
     threatMudFile = buildFilename(MUD_FILE_DIRECTORY, theFqdn, ".json");
     threatP7sFile = buildFilename(MUD_FILE_DIRECTORY, theFqdn, ".p7s");

     finalCmd = CURLCMD " -o " threatTmpFile " " Q9HOST "/" theFqdn;

     print "DEBUG: runQuad9(): Calling Quad9 on:" finalCmd;

     rc = system( finalCmd );
     if (rc == 0) {
         print "DEBUG: runQuad9(): Download success via Quad9 threat API.";
         threatTest = isQuad9Blocked(threatTmpFile);   

         if (threatTest == "true") {
             threatTest = isBlockedByProvider(threatTmpFile, THREATPROVIDER);

             if (threatTest == "true") {
                 print "DEBUG: runQuad9(): Threat provider " THREATPROVIDER ": They found " fqdn " to be bad. Call them now for more detailed threat response information.";
                 
                 retrieveThreatProviderFile(theFqdn, threatMudFile, "json");
                 retrieveThreatProviderFile(theFqdn, threatP7sFile, "p7s");

                 validSig = validateThreatMudFile(threatMudFile, threatP7sFile);

                 if (validSig == "true") {
                     print "DEBUG: runQuad9(): Installing valid mud file: " threatMudFile;
                     
                     installMudFile(threatMudFile, theFqdn, "lan", "wan");
                     installMudFile(threatMudFile, theFqdn, "wan", "lan");
                     
                     commitThreatConfiguration();
                 }
               
             } else {
                 print "DEBUG: runQuad9(): THREAT FOUND, but not via " THREATPROVIDER;
             }
         } else {
             print "DEBUG: runQuad9():...No threat found for " theFqdn;
         }
     } else {
         print "DEBUG: runQuad9(): Quad9 CALL FAILED RC: " rc;
         threatValue = "Q9_CALL_FAILED";
     }

     finalCmd = "rm -f " threatTmpFile;
     rc = system( finalCmd );
     if (rc != 0) {
         print "ERROR: runQuad9(): Could not clean up tmp file: " threatTmpFile;
     }
     
     return threatValue;
}

BEGIN {
    Q9HOST = "https://api.quad9.net/search"
    THREATHOST = "https://mud.threatstop.com"
    MUD_PROCESSOR_CMD = "/etc/q9thrt/build_policies.sh"
    COMMIT_CONFIG_CMD = "/etc/q9thrt/commit_threat_rules.sh"
    CURLCMD = "curl -s "
    JQCMD = "jq "
    THREATPROVIDER = "threatstop"
}
/NXDomain/
{ 
    CONTEXT = $10;
    FQDN = sanitizeInput(substr($11, 1, length($11)-1));

    if (CONTEXT == "A?") {
        print "=============================================";
        print $0;

        if (FQDN == "") {
            print "WARN: MAIN(): Ignoring empty FQDN"
        } else {
            if (index(FQDN, "://") == 0) {
                print CONTEXT " - " FQDN " - " Q9HOST;
                runQuad9(FQDN);
            } else {
                print "IGNORING: " FQDN
            }
        }
    }
}
'
