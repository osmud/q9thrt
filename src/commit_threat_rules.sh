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

# 1) Merge the ipset and firewall rules from the tmpConfigDir into the file state directory
# 2) Build the IPSET rules and install into /etc/firewall.user
# 3) Install the firewall rules into /etc/config/firewall
#         NOTE: Install IPSET declarations, allow rules, then reject rules in that order
#         NOTE: Install the firewall rules at the bottom of the existing ruleset. Allow user defined rules to execute first
# 4) Clean up the tmpConfigDir
# 5) Restart the firewall

USER_FIREWALL=/etc/firewall.user
FIREWALL_CONFIG_FILE=/etc/config/firewall

Q9_THRT_RULES_DIR=/etc/q9thrt/state/rules
BASE_RULES_FILE=/etc/q9/router-base-rules.conf

TMP_CONFIG_DIR="/tmp/q9thrt_tmp_dir"

APPLY_RULES=true
COUNT=-999

usage() { 
  echo "Usage: 
Required: -d <q9thrt-config-dir> -t <tmp-config-dir>" 1>&2; 
  exit 0; 
}

function test_config_files()
{
    FILE1=$1
    FILE2=$2

    echo "Testing files: ${FILE1} and ${FILE2}"

    if [ ! -f ${FILE1} ] || [ ! -f ${FILE2} ]; then
        echo "Either File1 or File2 not found! -- Apply rules"
    else
        echo "checking if they are the same"
        COUNT=$(diff ${FILE1} ${FILE2} | wc -l)

        if [ ${COUNT} == 0 ]; then
            echo "Files are the same. Do not apply changes."
            APPLY_RULES=false
        else
            echo "Files are different. Apply changes."
            APPLY_RULES=true
        fi
    fi
}

function reset_test_vars()
{
	APPLY_RULES=true
	COUNT=-999	
}
write_log()
{
    msg=$1
    echo `date -u +"%Y-%m-%dT%H:%M:%SZ"`$msg >> /tmp/q9thrt-firewall-mgmt.log
}

while getopts 'd:t:h' option; do
    case "${option}" in
    	d) Q9_THRT_RULES_DIR=$OPTARG;;
    	t) TMP_CONFIG_DIR=$OPTARG;;
	h | *) usage;;
    esac
done

if [[ -z "${Q9_THRT_RULES_DIR/ //}" ]]; then
    echo -e "ERROR: Please specify the IPSET configuration directory!\n"
    exit 1
fi

if [[ -z "${TMP_CONFIG_DIR/ //}" ]]; then
    echo -e "ERROR: Please specify the TMP configuration directory!\n"
    exit 1
fi

# Step 0: Restart DNSMASQ
/etc/init.d/dnsmasq restart

# Step 1: Create a backup of all files
#
rm -rf /tmp/q9thrt-backup2

mv /tmp/q9thrt-backup /tmp/q9thrt-backup2

mkdir -p /tmp/q9thrt-backup
cp ${Q9_THRT_RULES_DIR}/* /tmp/q9thrt-backup
cp ${USER_FIREWALL} /tmp/q9thrt-backup
cp ${FIREWALL_CONFIG_FILE} /tmp/q9thrt-backup

# Ensure the tmp direction is created and empty
mkdir -p $TMP_CONFIG_DIR
rm -f $TMP_CONFIG_DIR/*

# Step 2: Build the IPSET rules
#
#    NOTE: This will place the Q9 IPSET info at the end of the ipset configuration
#
sed '/# Q9THREATRULES start/,/# Q9THREATRULES end/d' ${USER_FIREWALL} > $TMP_CONFIG_DIR/q9.firewallIPSets

echo "# Q9THREATRULES start" >> $TMP_CONFIG_DIR/q9.firewallIPSets
echo "# " >> $TMP_CONFIG_DIR/q9.firewallIPSets
echo "# DO NOT EDIT THESE LINES. Q9THRT WILL REPLACE WITH ITS CONFIGURATION" >> $TMP_CONFIG_DIR/q9.firewallIPSets
echo "# " >> $TMP_CONFIG_DIR/q9.firewallIPSets

cat ${Q9_THRT_RULES_DIR}/*.q9_ipset >> $TMP_CONFIG_DIR/q9.firewallIPSets

echo "# Q9THREATRULES end" >> $TMP_CONFIG_DIR/q9.firewallIPSets

# Step 2a: Test if the new IPSET configuration is the same as the currently running file
#          We do not have to apply if it's the same as the running configuration.
#
reset_test_vars
test_config_files $TMP_CONFIG_DIR/q9.firewallIPSets ${USER_FIREWALL}

# Step 2b: If the files are different, we need to replace the current config file and apply the config
#
if $APPLY_RULES ; then
	write_log " +++ applying Q9 ipset rules"

    rm -f ${USER_FIREWALL}
    mv $TMP_CONFIG_DIR/q9.firewallIPSets ${USER_FIREWALL}
    
    source /etc/firewall.user
else
	write_log " --- NOT applying Q9 ipset rules"
fi


# Step 3: Install the firewall rules into /etc/config/firewall
#         NOTE: Install IPSET declarations, allow rules, then reject rules in that order
#         NOTE: Install the firewall rules at the bottom of the existing ruleset. Allow user defined rules to execute first
#
#    NOTE: We need to include the YIKES-AGENT RULES as well.
#              ORDER:    1) Base rules file
#                        2) Q9 rules
#
sed '/# Q9THREATRULES start/,/# Q9THREATRULES end/d' ${FIREWALL_CONFIG_FILE} > $TMP_CONFIG_DIR/q9.firewallRules

echo "# Q9THREATRULES start" >> $TMP_CONFIG_DIR/q9.firewallRules
echo "# " >> $TMP_CONFIG_DIR/q9.firewallRules
echo "# DO NOT EDIT THESE LINES. Q9THRT WILL REPLACE WITH ITS CONFIGURATION" >> $TMP_CONFIG_DIR/q9.firewallRules
echo "# " >> $TMP_CONFIG_DIR/q9.firewallRules

cat ${Q9_THRT_RULES_DIR}/*.q9_fw_ipset >> $TMP_CONFIG_DIR/q9.firewallRules
cat ${Q9_THRT_RULES_DIR}/*.q9_fw_rule >> $TMP_CONFIG_DIR/q9.firewallRules

echo "# Q9THREATRULES end" >> $TMP_CONFIG_DIR/q9.firewallRules

# Step 4a: Test if the new FIREWALL configuration is the same as the currently running file
#          We do not have to apply if it's the same as the running configuration.
#
reset_test_vars
test_config_files $TMP_CONFIG_DIR/q9.firewallRules ${FIREWALL_CONFIG_FILE}

# Step 4b: If the files are different, we need to replace the current config file and apply the config
#
if $APPLY_RULES ; then
	write_log " +++ applying Q9 FIREWALL rules"

    rm -f ${FIREWALL_CONFIG_FILE}
    mv $TMP_CONFIG_DIR/q9.firewallRules ${FIREWALL_CONFIG_FILE}
    
    /etc/init.d/firewall reload
else
	write_log " --- NOT applying Q9 FIREWALL rules"
fi

exit 0
