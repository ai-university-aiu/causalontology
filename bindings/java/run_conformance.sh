#!/bin/sh
set -e
cd "$(dirname "$0")"
mkdir -p out
javac -d out $(find src -name '*.java')
java -cp out org.causalontology.Conformance
