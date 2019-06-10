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

# Remove rules over 24 hours old and rebuild and reload the configuration
#
# Usage:
#
#

RULE_LOCATION="/etc/q9thrt/state/rules"
CONF_FILES="*.q9_*"

echo "****"
date
echo "Finding expired rules to be deleted. Rules to be expired shown below:"
echo "CMD: find $RULE_LOCATION -name $CONF_FILES -type f -mtime +1"
find $RULE_LOCATION -name $CONF_FILES -type f -mtime +1

echo "    ** FIND Complete. Purging these files and updating the firewall and DNS configuration"
find $RULE_LOCATION -name $CONF_FILES -type f -mtime +1 -exec rm -f {} \;

/etc/q9thrt/commit_threat_rules.sh
