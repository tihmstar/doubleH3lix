#!/bin/bash
xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO -sdk iphoneos
strip Build/Release-iphoneos/doubleH3lix.app/doubleH3lix 
