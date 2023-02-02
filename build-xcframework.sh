#!/usr/bin/env sh

NAME="anoncreds"
VERSION="0.1.0-dev.4"
BUNDLE_IDENTIFIER="org.hyperledger.$NAME"
LIBRARY_NAME="lib$NAME.dylib"
XC_FRAMEWORK_NAME="$NAME.xcframework"
FRAMEWORK_LIBRARY_NAME="`tr '[:lower:]' '[:upper:]' <<< ${NAME:0:1}`${NAME:1}"
FRAMEWORK_NAME="$FRAMEWORK_LIBRARY_NAME.framework"
HEADER_NAME="lib$NAME.h"
OUT_PATH="out"

# Setting some default paths
AARCH64_APPLE_IOS_PATH="./target/aarch64-apple-ios/release"
AARCH64_APPLE_IOS_SIM_PATH="./target/aarch64-apple-ios-sim/release"
X86_64_APPLE_IOS_PATH="./target/x86_64-apple-ios/release"
HEADER_PATH="./include"

# Simple helper command to display some information
Help() {
  echo "required dependencies:"
  echo "  - lipo"
  echo "  - xcodebuild"
  echo "To build an xcframework with underlying Frameworks"
  echo "the following can be passed in as positional arguments"
  echo "  1. Path to the aarch64-apple-ios where the dylib is stored"
  echo "  2. Path to the aarch64-apple-ios-sim where the dylib is stored"
  echo "  3. Path to the x86_64-apple-ios where the dylib is stored"
  echo "  4. Path to the header file, excluding the header"
  echo "Make sure to add the 'release' section of the path for a"
  echo "release build."
  exit
}

# Fail on execution error
# Print all commands
# Fail on undefined variables
# Do not mask piping errors
set -eo pipefail

# Check if lipo and xcodebuild exist
if [ -z `command -v lipo` ] || [ -z `command -v xcodebuild` ]
then
    echo "!!! lipo or xcodebuild could not be found !!!"
    help
fi

# override if its provided
if [ ! -z "$1" ]
then
  AARCH64_APPLE_IOS_PATH=$1
fi

# override if its provided
if [ ! -z "$2" ]
then
  AARCH64_APPLE_IOS_SIM_PATH=$2
fi

# override if its provided
if [ ! -z "$3" ]
then
  X86_64_APPLE_IOS_PATH=$3
fi

# override if its provided
if [ ! -z "$4" ]
then
  HEADER_PATH=$4
fi

if [ ! -f $AARCH64_APPLE_IOS_SIM_PATH/$LIBRARY_NAME ]
then
    echo "$AARCH64_APPLE_IOS_SIM_PATH/$LIBRARY_NAME does not exist!"
    exit
fi

if [ ! -f $AARCH64_APPLE_IOS_PATH/$LIBRARY_NAME ]
then
    echo "$AARCH64_APPLE_IOS_PATH/$LIBRARY_NAME does not exist!"
    exit
fi

if [ ! -f $X86_64_APPLE_IOS_PATH/$LIBRARY_NAME ]
then
    echo "$X86_64_APPLE_IOS_PATH/$LIBRARY_NAME does not exist!"
    exit
fi

if [ ! -f $HEADER_PATH/$HEADER_NAME ]
then
    echo "$HEADER_PATH/$HEADER_NAME does not exist!"
    exit
fi

# Displaying the supplied paths to the user 
# So there will not be any mistakes
cat << EOF
Using $AARCH64_APPLE_IOS_PATH for aarch64-apple-ios
Using $AARCH64_APPLE_IOS_SIM_PATH for aarch64-apple-ios-sim
Using $X86_64_APPLE_IOS_PATH for x86_64-apple-ios

Building xcframework with the following values:

Name:                   $NAME
Version:                $VERSION
Bundle identifier:      $BUNDLE_IDENTIFIER
Library name:           $LIBRARY_NAME
Framework name:         $FRAMEWORK_NAME
XCFramework name:       $XC_FRAMEWORK_NAME
Framework library name: $FRAMEWORK_LIBRARY_NAME

EOF

echo "Setting op output directory in $OUT_PATH"
mkdir $OUT_PATH

echo "Combining aarch64 and x86-64 for the simulator.."
lipo -create $AARCH64_APPLE_IOS_SIM_PATH/$LIBRARY_NAME \
             $X86_64_APPLE_IOS_PATH/$LIBRARY_NAME \
     -output $OUT_PATH/sim-$LIBRARY_NAME

echo "Creating a framework template..."
mkdir $OUT_PATH/$FRAMEWORK_NAME
cd $OUT_PATH/$FRAMEWORK_NAME
mkdir Headers
cp ../../$HEADER_PATH/$HEADER_NAME Headers/$FRAMEWORK_LIBRARY_NAME.h
mkdir Modules
touch Modules/module.modulemap
cat <<EOT >> Modules/module.modulemap
framework module $FRAMEWORK_LIBRARY_NAME {
  umbrella header "$FRAMEWORK_LIBRARY_NAME.h"

  export *
  module * { export * }
}
EOT

cat <<EOT >> Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleExecutable</key>
	<string>$FRAMEWORK_LIBRARY_NAME</string>
	<key>CFBundleIdentifier</key>
	<string>$BUNDLE_IDENTIFIER</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>$NAME</string>
	<key>CFBundlePackageType</key>
	<string>FMWK</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleVersion</key>
	<string>0.1.0</string>
	<key>NSPrincipalClass</key>
	<string></string>
</dict>
</plist>
EOT

cd ..

echo "Creating both frameworks (real device and simulator)..."
mkdir sim
mkdir real
cp -r $FRAMEWORK_NAME sim/
cp -r $FRAMEWORK_NAME real/
mv sim-$LIBRARY_NAME sim/$FRAMEWORK_NAME/$FRAMEWORK_LIBRARY_NAME
cp ../$AARCH64_APPLE_IOS_PATH/$LIBRARY_NAME real/$FRAMEWORK_NAME/$FRAMEWORK_LIBRARY_NAME

echo "Creating XC Framework..."
xcodebuild -create-xcframework \
           -framework  sim/$FRAMEWORK_NAME \
           -framework real/$FRAMEWORK_NAME \
           -output $XC_FRAMEWORK_NAME

echo "cleaning up..."
rm -rf $FRAMEWORK_NAME real sim

echo "Framework written to $OUT_PATH/$XC_FRAMEWORK_NAME"
