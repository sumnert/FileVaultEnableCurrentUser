#!/bin/bash

###############################################################################
###############################################################################
#
# 	THIS SCRIPT IS NOT AN OFFICIAL PRODUCT OF JAMF SOFTWARE
# 	AS SUCH IT IS PROVIDED WITHOUT WARRANTY OR SUPPORT
#
###############################################################################
#
#	BY USING THIS SCRIPT, YOU AGREE THAT JAMF SOFTWARE IS UNDER NO OBLIGATION
#   	TO SUPPORT, DEBUG, OR OTHERWISE	MAINTAIN THIS SCRIPT
#
###############################################################################
#
#	THIS SCRIPT IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
#	INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
#   	AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
#	JAMF SOFTWARE, LLC BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#	EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
#	OF SUBSTITUTE GOODS OR SERVICES;LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#	IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#	POSSIBILITY OF SUCH DAMAGE.	
#
###############################################################################
###############################################################################
#
#            Name:  FileVaultEnableCurrentUser.sh
#     Description:  This script is intended to run on Macs which need a
#                   add the Current User as a FileVault enabled user.
#         Credits:  https://github.com/homebysix
#		    https://github.com/kc9wwh
#                   https://github.com/ToplessBanana
#                   https://github.com/brysontyrrell
#                   https://www.jamf.com/jamf-nation/articles/146
#       Tested On:  macOS 10.15, 10.14, 10.13
#         Created:  2018-03-21
#   Last Modified:  2020-07-30 - Modified https://github.com/kc9wwh script to
#				pass Filevault to Current User from Admin User
#
###############################################################################
#
#	   Created By:  Josh Roskos
#	  Modified By:  Tyler Sumner
#
###############################################################################

################################## VARIABLES ##################################

# Company logo. (Tested with PNG, JPG, GIF, PDF, and AI formats.)
LOGO="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/FileVaultIcon.icns"

# The title of the message that will be displayed to the user.
# Not too long, or it'll get clipped.
PROMPT_TITLE="Encryption Update Required"

# The body of the message that will be displayed before prompting the user for
# their password. All message strings below can be multiple lines.
PROMPT_MESSAGE="Per Information Security requirements, we need to update the encryptions settings on your mac.
Please click the Next button below, then enter your Mac's password when prompted."

# The body of the message that will be displayed after 5 incorrect passwords.
FORGOT_PW_MESSAGE="Please contact the help desk for help with your Mac password."

# The body of the message that will be displayed if a failure occurs.
FAIL_MESSAGE="Sorry, an error occurred while updating your Encryption settings. Please contact the help desk for assistance."

# Specify the admin or managmenet account that you want FileVault enabled.
#************************************************************************************
# BEWARE: DURING EXECUTION OF SCRIPT IT IS POSSIBLE FOR ATTACKERS TO DECRPYT AND GET THE ADMIN PASSWORD
ADMIN_USER_ENCRYPTED="$4"
ADMIN_PASS_ENCRYPTED="$5"
SALT="$6"
PASSPHRASE="$7"
#************************************************************************************

###############################################################################
######################### DO NOT EDIT BELOW THIS LINE #########################
###############################################################################

################################## FUNCTIONS ##################################

# Decrypts admin username and password
function DecryptString() {
	# Usage: ~$ DecryptString "Encrypted String" "Salt" "Passphrase"
	echo "${1}" | /usr/bin/openssl enc -aes256 -d -a -A -S "$SALT" -k "$PASSPHRASE"
}

# Enables SecureToken for the user account.
enableSecureToken() {
	sysadminctl -adminUser $ADMIN_USER -adminPassword $ADMIN_PASS -secureTokenOn $CURRENT_USER -password $USER_PASS
}

# Creates a PLIST containing the necessary administrator and user credentials.
createPlist() {
	# Translate XML reserved characters to XML friendly representations.
	USER_PASS=${USER_PASS//&/&amp;}
	USER_PASS=${USER_PASS//</&lt;}
	USER_PASS=${USER_PASS//>/&gt;}
	USER_PASS=${USER_PASS//\"/&quot;}
	USER_PASS=${USER_PASS//\'/&apos;}
	
	echo '<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
	<key>Username</key>
	<string>'$ADMIN_USER'</string>
	<key>Password</key>
	<string>'$ADMIN_PASS'</string>
	<key>AdditionalUsers</key>
	<array>
		<dict>
			<key>Username</key>
			<string>'$CURRENT_USER'</string>
			<key>Password</key>
			<string>'$USER_PASS'</string>
		</dict>
	</array>
	</dict>
	</plist>' > /private/tmp/userToAdd.plist
}

# Adds the user account to the list of FileVault enabled users.
addUser() {
	sudo fdesetup add -i < /private/tmp/userToAdd.plist
}

# Update the preboot role volume's subject directory.
updatePreboot() {
	diskutil apfs updatePreboot /
}

# Deletes the PLIST containing the administrator and user credentials.
cleanUp() {
	rm /private/tmp/userToAdd.plist
	unset USER_PASS
}

######################## VALIDATION AND ERROR CHECKING ########################

# Suppress errors for the duration of this script. (This prevents JAMF Pro from
# marking a policy as "failed" if the words "fail" or "error" inadvertently
# appear in the script output.)
exec 2>/dev/null

BAILOUT=false

# Make sure we have root privileges (for fdesetup).
if [[ $EUID -ne 0 ]]; then
	REASON="This script must run as root."
	BAILOUT=true
fi

# Check for remote users.
REMOTE_USERS=$(/usr/bin/who | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | wc -l)
if [[ $REMOTE_USERS -gt 0 ]]; then
	REASON="Remote users are logged in."
	BAILOUT=true
fi

# Make sure the custom logo file is present.
if [[ ! -f "$LOGO" ]]; then
	REASON="Custom logo not present: $LOGO"
	BAILOUT=true
fi

# Convert POSIX path of logo icon to Mac path for AppleScript
LOGO_POSIX="$(/usr/bin/osascript -e 'tell application "System Events" to return POSIX file "'"$LOGO"'" as text')"

# Bail out if jamfHelper doesn't exist.
jamfHelper="/Library/Application Support/JAMF/bin/jamfHelper.app/Contents/MacOS/jamfHelper"
if [[ ! -x "$jamfHelper" ]]; then
	REASON="jamfHelper not found."
	BAILOUT=true
fi

# Check the OS version.
OS_MAJOR=$(/usr/bin/sw_vers -productVersion | awk -F . '{print $1}')
OS_MINOR=$(/usr/bin/sw_vers -productVersion | awk -F . '{print $2}')
if [[ "$OS_MAJOR" -ne 10 || "$OS_MINOR" -lt 9 ]]; then
	REASON="This script requires macOS 10.9 or higher. This Mac has $(sw_vers -productVersion)."
	BAILOUT=true
fi

# Get the logged in user's name
CURRENT_USER=$(/usr/bin/python -c 'from SystemConfiguration import SCDynamicStoreCopyConsoleUser; import sys; username = (SCDynamicStoreCopyConsoleUser(None, None, None) or [None])[0]; username = [username,""][username in [u"loginwindow", None, u""]]; sys.stdout.write(username + "\n");')

# Make sure there's an actual user logged in
if [[ -z $CURRENT_USER || "$CURRENT_USER" == "root" ]]; then
	REASON="No user is currently logged in."
	BAILOUT=true
fi

# Check if volume is using HFS+ or APFS
FILESYSTEM_TYPE=$(/usr/sbin/diskutil info / | awk '/Type \(Bundle\)/ {print $3}')

################################ MAIN PROCESS #################################

# Decrypt Admin Account Credentials
ADMIN_USER=$(DecryptString ${ADMIN_USER_ENCRYPTED})
ADMIN_PASS=$(DecryptString ${ADMIN_PASS_ENCRYPTED})

# Get information necessary to display messages in the current user's context.
USER_ID=$(/usr/bin/id -u "$CURRENT_USER")
if [[ "$OS_MAJOR" -eq 10 && "$OS_MINOR" -le 9 ]]; then
	L_ID=$(/usr/bin/pgrep -x -u "$USER_ID" loginwindow)
	L_METHOD="bsexec"
elif [[ "$OS_MAJOR" -eq 10 && "$OS_MINOR" -gt 9 ]]; then
	L_ID=$USER_ID
	L_METHOD="asuser"
fi

# If any error occurred in the validation section, bail out.
if [[ "$BAILOUT" == "true" ]]; then
	echo "[ERROR]: $REASON"
	launchctl "$L_METHOD" "$L_ID" "$jamfHelper" -windowType "utility" -icon "$LOGO" -title "$PROMPT_TITLE" -description "$FAIL_MESSAGE: $REASON." -button1 'OK' -defaultButton 1 -startlaunchd &>/dev/null &
	exit 1
fi

echo "Checking to make sure $ADMIN_USER is present..."
if [[ $(dscl . list /Users) =~ "$ADMIN_USER" ]]; then
	echo "$ADMIN_USER is present."
else
	echo "$ADMIN_USER not found. $CURRENT_USER was not enabled Filevault"
	exit 1
fi

# Display a branded prompt explaining the password prompt.
echo "Alerting user $CURRENT_USER about incoming password prompt..."
/bin/launchctl "$L_METHOD" "$L_ID" "$jamfHelper" -windowType "utility" -icon "$LOGO" -title "$PROMPT_TITLE" -description "$PROMPT_MESSAGE" -button1 "Next" -defaultButton 1 -startlaunchd &>/dev/null

# Get the logged in user's password via a prompt.
echo "Prompting $CURRENT_USER for their Mac password..."
USER_PASS="$(/bin/launchctl "$L_METHOD" "$L_ID" /usr/bin/osascript -e 'display dialog "Please enter the password you use to log in to your Mac:" default answer "" with title "'"${PROMPT_TITLE//\"/\\\"}"'" giving up after 86400 with text buttons {"OK"} default button 1 with hidden answer with icon file "'"${LOGO_POSIX//\"/\\\"}"'"' -e 'return text returned of result')"

# Thanks to James Barclay (@futureimperfect) for this password validation loop.
TRY=1
until /usr/bin/dscl /Search -authonly "$CURRENT_USER" "$USER_PASS" &>/dev/null; do
	(( TRY++ ))
	echo "Prompting $CURRENT_USER for their Mac password (attempt $TRY)..."
	USER_PASS="$(/bin/launchctl "$L_METHOD" "$L_ID" /usr/bin/osascript -e 'display dialog "Sorry, that password was incorrect. Please try again:" default answer "" with title "'"${PROMPT_TITLE//\"/\\\"}"'" giving up after 86400 with text buttons {"OK"} default button 1 with hidden answer with icon file "'"${LOGO_POSIX//\"/\\\"}"'"' -e 'return text returned of result')"
	if (( TRY >= 5 )); then
		echo "[ERROR] Password prompt unsuccessful after 5 attempts. Displaying \"forgot password\" message..."
		/bin/launchctl "$L_METHOD" "$L_ID" "$jamfHelper" -windowType "utility" -icon "$LOGO" -title "$PROMPT_TITLE" -description "$FORGOT_PW_MESSAGE" -button1 'OK' -defaultButton 1 -startlaunchd &>/dev/null &
		exit 1
	fi
done
echo "Successfully prompted for Mac password."

# if macOS 10.13 or later enable SecureToken first
if [[ "$OS_MINOR" -ge 13 ]]; then
	echo "System is running macOS $OS_MAJOR.$OS_MINOR."
	# Enables SecureToken for the user account.
	if [[ "$FILESYSTEM_TYPE" == "apfs" ]]; then
		echo "Enabling SecureToken..."
		enableSecureToken
		# Check and see if account is now FileVault enabled
		ADMIN_FV_STATUS=$(sysadminctl -adminUser $ADMIN_USER -adminPassword $ADMIN_PASS -secureTokenStatus $CURRENT_USER 2>&1)
		SECURE_TOKEN_STATUS=$(echo $ADMIN_FV_STATUS | sed -e 's/.*is\(.*\).for.*/\1/')
		if [[ "$SECURE_TOKEN_STATUS" == *"ENABLED"* ]]; then
			echo "$CURRENT_USER has been granted a SecureToken..."
		fi
	fi
	#Checking to see if we need to add the User to Filevault
	FV_STATUS="$(/usr/bin/fdesetup status)"
	if grep -q "FileVault is On" <<< "$FV_STATUS"; then
		
		echo "Making $CURRENT_USER FileVault Enabled..."
		# FileVault enable admin account
		createPlist
		addUser
		# Check if current user account is not FileVault ENABLED
		FV2_CHECK=$(fdesetup list | awk -v usrN="$CURRENT_USER" -F, 'match($0, usrN) {print $1}')
		if [[ "$FV2_CHECK" == "${CURRENT_USER}" ]]; then
			echo "$CURRENT_USER is now FileVault Enabled."
			if [[ "$FILESYSTEM_TYPE" == "apfs" ]]; then
				echo "Updating APFS Preboot..."
				updatePreboot
				fi
		else
			echo "Error making $CURRENT_USER FileVault Enabled."
		fi
	else
		echo "User was not added to Filevault because: $FV_STATUS"
	fi

elif [[ "$OS_MINOR" -le 12 ]]; then
	echo "System is running macOS $OS_MAJOR.$OS_MINOR."
	echo "Making $CURRENT_USER FileVault Enabled..."
	# FileVault enable admin account
	createPlist
	addUser
	# Check if current account is not FileVault ENABLED
	FV2_CHECK=$(fdesetup list | awk -v usrN="$CURRENT_USER" -F, 'match($0, usrN) {print $1}')
	if [[ "$FV2_CHECK" == "${CURRENT_USER}" ]]; then
		echo "$CURRENT_USER is now FileVault Enabled."
	else
		echo "Error making $CURRENT_USER FileVault Enabled."
	fi
fi

cleanUp

exit 0
