#!/usr/bin/env bash
set -euo pipefail

# Adapted from snyk/ads-distribution-service/scripts/sign_macos.sh, which is in
# turn based on https://github.com/snyk/cli/blob/main/cliv2/scripts/sign_darwin.sh
#
# Signs and notarizes a single macOS binary in place, then records informational
# signing metadata in <binary>.signingmeta.
#
# expected environment variables
#APPLE_ID=AAA
#APPLE_APP_PASSWORD=BBB
#APPLE_TEAM_ID=CCC
#APPLE_SIGNING_IDENTITY="DDD"
#APPLE_SIGNING_SECRETS_BINARY=EEE....   # base64-encoded .p12
#APPLE_SIGNING_SECRETS_PASSWORD=FFF

EXPORT_PATH=${1:-./dist}
PRODUCT_NAME=${2:-snyk-studio-macos-arm64}
APP_PATH="$EXPORT_PATH/$PRODUCT_NAME"
ZIP_PATH="$EXPORT_PATH/$PRODUCT_NAME.zip"
APPLE_SIGNING_SECRETS="AppleCodeSigningSecrets.p12"
KEYCHAIN_NAME=CodeSigningChain
KEYCHAIN_PASSWORD=123456
KEYCHAIN_PROFILE="SNYK-STUDIO"
KEYCHAIN_FILE="$HOME/Library/Keychains/$KEYCHAIN_NAME-db"
OLD_KEYCHAIN_NAMES=$(security list-keychains | sed -E -e ':a' -e 'N' -e '$!ba' -e 's/\n//g' -e 's/ //g' -e 's/""/" "/g')
CODESIGN_ENTITLEMENTS="" # no entitlements for the studio installer

LOG_PREFIX="--- $(basename "$0"):"

echo "$LOG_PREFIX Signing & notarizing \"$APP_PATH\""

if [[ "$OSTYPE" != *"darwin"* ]]; then
  echo "$LOG_PREFIX ERROR! This script needs to be run on macOS!"
  exit 1
fi

# If the required secrets are not available we skip signing without an error so
# local builds still succeed. The binary is recorded as unsigned; a later
# is-signed check in the build pipeline catches this if it was unexpected.
if [ -z "${APPLE_ID+x}" ]; then
  echo "$LOG_PREFIX Signing secrets are unavailable; recording binary as unsigned."
  {
    echo "signed=false"
    echo "signing_identity="
  } > "$APP_PATH.signingmeta"
  exit 0
fi

#
# prepare signing infrastructure
#
echo "$LOG_PREFIX Creating p12 file"
echo "$APPLE_SIGNING_SECRETS_BINARY" | base64 --decode > "$APPLE_SIGNING_SECRETS"

echo "$LOG_PREFIX Adding temporary keychain"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_NAME"
security list-keychains -s "$KEYCHAIN_NAME"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_NAME"

# import signing secrets into key chain
echo "$LOG_PREFIX Importing p12 file into temporary keychain"
security import "$APPLE_SIGNING_SECRETS" -P "$APPLE_SIGNING_SECRETS_PASSWORD" -k "$KEYCHAIN_NAME" -T /usr/bin/codesign
rm $APPLE_SIGNING_SECRETS
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_NAME"

# wait for security commands to finish before running codesign
sleep 30

echo "$LOG_PREFIX Signing binary $APP_PATH"

codesign -f -s "$APPLE_SIGNING_IDENTITY" -v "$APP_PATH" --timestamp --options runtime $CODESIGN_ENTITLEMENTS

# create a zip file
echo "$LOG_PREFIX Creating zip file $ZIP_PATH"
/usr/bin/ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"

# add notarization credentials to keychain for later usage
echo "$LOG_PREFIX Preparing notarization"
xcrun notarytool store-credentials "$KEYCHAIN_PROFILE" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD" --keychain "$KEYCHAIN_FILE"

# notarize & wait
echo "$LOG_PREFIX Running notarization"
xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$KEYCHAIN_PROFILE" --wait

# record informational signing metadata.
# awk consumes the whole stream (no early exit) so codesign is never SIGPIPE'd,
# which would otherwise abort this script under `set -o pipefail`.
SIGNING_IDENTITY=$(codesign -dvv "$APP_PATH" 2>&1 | awk -F= '/^Authority=/ && v==""{v=$2} END{print v}')
echo "$LOG_PREFIX Recording signing metadata (identity: $SIGNING_IDENTITY)"
{
  echo "signed=true"
  echo "signing_identity=$SIGNING_IDENTITY"
} > "$APP_PATH.signingmeta"

# cleanup
echo "$LOG_PREFIX Cleaning up"
security list-keychains -s "$OLD_KEYCHAIN_NAMES"
security delete-keychain "$KEYCHAIN_NAME"
rm "$ZIP_PATH"
