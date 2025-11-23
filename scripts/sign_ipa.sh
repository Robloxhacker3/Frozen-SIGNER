#!/usr/bin/env bash
# scripts/sign_ipa.sh
# Usage: ./sign_ipa.sh /absolute/path/to/jobdir p12_password
set -e
JOBDIR="$1"
P12PW="$2"

if [ -z "$JOBDIR" ]; then
  echo "Usage: $0 jobdir p12_password" >&2
  exit 2
fi

cd "$JOBDIR"
echo "Working in $(pwd)"

# Expect files: orig.ipa, cert.p12, profile.mobileprovision
if [ ! -f orig.ipa ]; then echo "orig.ipa missing"; exit 3; fi
if [ ! -f cert.p12 ]; then echo "cert.p12 missing"; exit 4; fi
if [ ! -f profile.mobileprovision ]; then echo "profile.mobileprovision missing"; exit 5; fi

TMPKEYCHAIN="$JOBDIR/tmp.keychain"
KEYCHAINPW="tmpkeychainpw$(date +%s)"

# Create temporary keychain and import p12
echo "Creating keychain..."
security create-keychain -p "$KEYCHAINPW" "$TMPKEYCHAIN"
security default-keychain -s "$TMPKEYCHAIN"
security unlock-keychain -p "$KEYCHAINPW" "$TMPKEYCHAIN"
security import cert.p12 -k "$TMPKEYCHAIN" -P "$P12PW" -T /usr/bin/codesign || {
  echo "p12 import failed";
  exit 6;
}

# Find identity name
IDENTITY=$(security find-identity -v -p codesigning "$TMPKEYCHAIN" | awk -F\" '/"/{print $2; exit}')
if [ -z "$IDENTITY" ]; then
  echo "Could not find codesigning identity"
  exit 7
fi
echo "Using identity: $IDENTITY"

# Unzip IPA
rm -rf payload
mkdir -p tmpunpack
cd tmpunpack
unzip -q ../orig.ipa
if [ ! -d Payload ]; then echo "Payload missing"; exit 8; fi

APPPATH=$(ls -1 Payload | grep '\.app$' | head -n1)
if [ -z "$APPPATH" ]; then echo "App path not found"; exit 9; fi
echo "Found app: $APPPATH"

# Replace provisioning profile
cp ../profile.mobileprovision "Payload/$APPPATH/embedded.mobileprovision"
echo "Replaced provisioning profile"

# Optionally modify display name, icon, bundle id — advanced editing not included in this template.
# Re-sign frameworks and extensions (if any)
echo "Re-signing frameworks and extensions..."
# resign function
resign_entitlements() {
  BIN="$1"
  echo "Signing $BIN"
  /usr/bin/codesign --force --timestamp --sign "$IDENTITY" --preserve-metadata=entitlements,identifier,requirements "$BIN"
}

# Sign all frameworks
if [ -d "Payload/$APPPATH/Frameworks" ]; then
  for f in Payload/"$APPPATH"/Frameworks/*; do
    if [ -f "$f" ]; then
      resign_entitlements "$f"
    fi
  done
fi

# Sign app binary
resign_entitlements "Payload/$APPPATH"

# Verify
echo "Verifying signature..."
/usr/bin/codesign -vvv --deep --strict "Payload/$APPPATH" || {
  echo "codesign verification failed"
  # continue so user can inspect output/logs
}

# Repackage
cd ..
rm -f signed.ipa
zip -qr signed.ipa tmpunpack/Payload
mv signed.ipa ../signed.ipa
echo "Signed IPA created at ../signed.ipa"

# Cleanup: delete temp keychain
security delete-keychain "$TMPKEYCHAIN" || true
echo "Done"
exit 0
