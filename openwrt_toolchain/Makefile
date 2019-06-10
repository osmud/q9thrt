# Copyright 2018 osMUD
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

include $(TOPDIR)/rules.mk

# Name, version and release number
# The name and version of your package are used to define the variable to point to the build directory of your package: $(PKG_BUILD_DIR)
PKG_NAME:=Quad9ThreatResponse
PKG_VERSION:=0.3.0
PKG_RELEASE:=1

# Source settings (i.e. where to find the source codes)
# This is a custom variable, used below
SOURCE_DIR:=/home/lede/q9thrt

include $(INCLUDE_DIR)/package.mk

# Package definition; instructs on how and where our package will appear in the overall configuration menu ('make menuconfig')
define Package/q9thrt
  SECTION:=net
  CATEGORY:=Base system
  TITLE:=GCA Quad9 threat_signaling
  DEPENDS:=+libcurl +curl +ca-bundle +jq +openssl-util +ca-certificates +ipset +logrotate +tcpdump
endef

# Package description; a more verbose description on what our package does
define Package/q9thrt/description
  q9thrt- see https://github.com/osmud/q9thrt repo.
endef

# Package preparation instructions; create the build directory and copy the source code. 
# The last command is necessary to ensure our preparation instructions remain compatible with the patching system.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -R $(SOURCE_DIR)/* $(PKG_BUILD_DIR)
#	$(Build/Patch)
endef

# Package build instructions; invoke the target-specific compiler to first compile the source file, and then to link the file into the final executable
define Build/Compile
	echo compiling
endef

# Package install instructions; create a directory inside the package to hold our executable, and then copy the executable we built previously into the folder
define Package/q9thrt/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/q9thrt
	$(INSTALL_DIR) $(1)/etc/crontabs
	$(INSTALL_DIR) $(1)/etc/dnsmasq.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/dnsmasq.base-settings.conf $(1)/etc/q9thrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/q9thrt.cron $(1)/etc/q9thrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/resolv.conf $(1)/etc/q9thrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/firewall.q9sample.conf $(1)/etc/q9thrt/firewall.q9.conf
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/dhcp.q9sample.conf $(1)/etc/q9thrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/logrotate.conf $(1)/etc/q9thrt
	
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/q9thrt.init $(1)/etc/init.d/q9thrt	
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/threat_filter.sh $(1)/etc/q9thrt/threat_filter.sh	
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/build_policies.sh $(1)/etc/q9thrt/build_policies.sh
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/remove_expired_rules.sh $(1)/etc/q9thrt/remove_expired_rules.sh
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/commit_threat_rules.sh $(1)/etc/q9thrt/commit_threat_rules.sh

	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/dnsmasq.q9thrt.conf $(1)/etc/dnsmasq.d/15-q9thrt.conf
endef

define Package/q9thrt/postinst
#!/bin/sh
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
        echo "Enabling rc.d symlink for GCA Quad9 Threat Response and enabling cron"
        touch /etc/crontabs/root
        cat /etc/q9thrt/q9thrt.cron >> /etc/crontabs/root
        cat /etc/q9thrt/firewall.q9.conf >> /etc/config/firewall
        cat /etc/q9thrt/dnsmasq.base-settings.conf >> /etc/dnsmasq.conf
        /etc/init.d/dnsmasq restart
        /etc/init.d/firewall restart
        /etc/init.d/cron start
        /etc/init.d/cron enable        
        /etc/init.d/q9thrt enable
fi
exit 0
endef

define Package/q9thrt/prerm
#!/bin/sh
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
        echo "Removing rc.d symlink for q9thrt"
        /etc/init.d/q9thrt disable
fi
exit 0
endef
# This command is always the last, it uses the definitions and variables we give above in order to get the job done
$(eval $(call BuildPackage,q9thrt))
