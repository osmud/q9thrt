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

#
# Usage:
#      This will use as input the MUD file, and ACL point, and create IP-based firewall rules for a threat intel provider MUD
#      file that describes a threat. This process will install directional firewall rules for both inbound and outbound traffic
#      to protect against all FQDN's and IP addresses identified as being part of this threat. Two artificacts will be produced. The
#      first is a table if IP addresses using IPSET syntax. The second are firewall rule syntax to be installed into the OpenWRT UCI
#      firewall controlling the traffic and referencing the IPSET.
#
#      These artificats will be installed into both the OpenWRT firewall and DNSMASQ DNS server configurations for implementation.
#

BASEDIR=`dirname "$0"`
usage() { 
  echo "Usage: 
Required: -e <ipset-name> -m <mud file> -s <src-zone>  -d <dest-zone> -k <rule state directory>" 1>&2; 
  exit 0; 
}

SRC=""
DEST=""
IPSET_NAME=""
MUD_FILE=""
DIRECTION=""

TARGET="REJECT"
PROTO="all"
SRC_PORT="any"
DEST_PORT="any"
FAMILY="ipv4"
MUD_TMP_STATE_DIR="/etc/q9thrt/state/rules"

while getopts 'hs:i:d:j:e:k:m:' option; do
    case "${option}" in
    m) MUD_FILE=$OPTARG;;
    s) SRC=$OPTARG;;
    d) DEST=$OPTARG;;
    e) IPSET_NAME=${OPTARG//\./_};;
    k) MUD_TMP_STATE_DIR=$OPTARG;;
    h | *) usage;;
    esac
done

if [[ -z "${MUD_FILE/ //}" ]]; then
    echo -e "ERROR: Please specify the MUD file location (-m <mud file with path>)!\n"
    exit 1
fi

if [[ -z "${MUD_TMP_STATE_DIR/ //}" ]]; then
    echo -e "ERROR: Please specify the MUD State configuration directory (-k <directory>)!\n"
    exit 1
fi

if [[ -z "${PROTO/ //}" ]]; then
    echo -e "ERROR: Plese specify protocol [tcp|udp|all].\n"
    exit 1
fi

if [[ -z "${SRC/ //}" ]]; then
    echo -e "ERROR: Plese specify source zone!\n"
    exit 1
fi

if [[ -z "${DEST/ //}" ]]; then
    echo -e "ERROR: Plese specify dest zone!\n"
    exit 1
fi

if [[ -z "${IPSET_NAME/ //}" ]]; then
    echo -e "ERROR: Please specify [-e ipset-name].\n"
    exit 1
fi

# We currently only support ipv4. If you ask for all, set to ipv4
if [ ${FAMILY} == 'all' ]; then
    FAMILY='ipv4'
fi

if [ ${SRC} == 'lan' ]; then
    DIRECTION='FD'
    FW_FIELD="src_ip"
    IPSET_MATCH_FIELD="dest_ip"
fi

if [ ${DEST} == 'lan' ]; then
    DIRECTION='TD'
    FW_FIELD="dest_ip"
    IPSET_MATCH_FIELD="src_ip"
fi

#
# Step 1 Build IPSET
#
FINAL_IPSET_NAME="Q9TS-${IPSET_NAME}${DIRECTION}"
FULLFILE="${MUD_TMP_STATE_DIR}/${FINAL_IPSET_NAME}.q9_ipset"
IPSETFWDEF="${MUD_TMP_STATE_DIR}/${FINAL_IPSET_NAME}.q9_fw_ipset"

# Overwrite the IPSET definitions even if they exists. The threat may have changed.

touch $FULLFILE
echo "if ! ipset list|grep ${FINAL_IPSET_NAME}; then ipset create ${FINAL_IPSET_NAME} hash:ip netmask 30 timeout 0; fi"  > $FULLFILE
echo " " >> $FULLFILE
echo "ipset flush ${FINAL_IPSET_NAME}" >> $FULLFILE
echo " " >> $FULLFILE
   
touch $IPSETFWDEF
echo " " > $IPSETFWDEF
echo "config ipset" >> $IPSETFWDEF
echo "    option enabled 1" >> $IPSETFWDEF
echo "    option name ${FINAL_IPSET_NAME}" >> $IPSETFWDEF
echo "    option match ${IPSET_MATCH_FIELD}" >> $IPSETFWDEF
echo "    option storage hash" >> $IPSETFWDEF
echo "    option family ipv4" >> $IPSETFWDEF
echo "    option external ${FINAL_IPSET_NAME}" >> $IPSETFWDEF

#
# Step 2 Build Firewall rules
#

FINAL_RULE_NAME="${FINAL_IPSET_NAME}"
RULE_FILENAME="${MUD_TMP_STATE_DIR}/${FINAL_IPSET_NAME}.q9_fw_rule"

touch ${RULE_FILENAME}

echo " " > ${RULE_FILENAME}
echo "config rule" >> ${RULE_FILENAME}
echo "        option enabled   '1'"       >> ${RULE_FILENAME}
echo "        option name      '${FINAL_RULE_NAME}'" >> ${RULE_FILENAME}
echo "        option target    ${TARGET}" >> ${RULE_FILENAME}
echo "        option src       ${SRC}"    >> ${RULE_FILENAME}
echo "        option dest      ${DEST}"   >> ${RULE_FILENAME}
echo "        option proto     ${PROTO}"  >> ${RULE_FILENAME}
echo "        option family    ${FAMILY}" >> ${RULE_FILENAME}
echo "        option ipset     ${FINAL_IPSET_NAME}" >> ${RULE_FILENAME}
echo "        option ${FW_FIELD}    any" >> ${RULE_FILENAME}


#
# Step 3 now parse the mudfile and add the IP's to the IPSET
#        This set is regenerated every time based on the contents of the threat MUD file
#        Execute the "jq" command to collect the list of IP's and add them to the file
#
rm -f /tmp/input

if [ ${DIRECTION} == 'FD' ]; then
    jq -r '.["ietf-access-control-list:acls"].acl[].aces.ace[].matches["destination-ipv4-network"]["net:ipv4-prefix"]' $MUD_FILE | grep -v null > /tmp/input
else
    jq -r '.["ietf-access-control-list:acls"].acl[].aces.ace[].matches["source-ipv4-network"]["net:ipv4-prefix"]' $MUD_FILE | grep -v null > /tmp/input
fi

while read THREAT_IP
do
    echo "ipset add ${FINAL_IPSET_NAME} ${THREAT_IP} " >> ${FULLFILE}
done < /tmp/input

rm -f /tmp/input

#
# Step 4 now reparse the mudfile to extract the associated domains and add to the local dns-sinkhole configuration
#
FINAL_SINKHOLE_NAME="${MUD_TMP_STATE_DIR}/Q9TS-${FINAL_IPSET_NAME}.q9_dns_conf"

rm -f /tmp/dnsinput

if [ ${DIRECTION} == 'FD' ]; then
    jq -r '.["ietf-access-control-list:acls"].acl[].aces.ace[].matches.ipv4["ietf-acldns:dst-dnsname"]' $MUD_FILE | grep -v null > /tmp/dnsinput
else
    jq -r '.["ietf-access-control-list:acls"].acl[].aces.ace[].matches.ipv4["ietf-acldns:src-dnsname"]' $MUD_FILE | grep -v null > /tmp/dnsinput
fi

touch ${FINAL_SINKHOLE_NAME}

while read THREAT_FQDN
do
    echo "address=/${THREAT_FQDN}/127.0.0.1" >> ${FINAL_SINKHOLE_NAME}
done < /tmp/dnsinput

rm -f /tmp/dnsinput


exit 0
