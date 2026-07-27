#!/bin/sh
# Build bindings/java/target/causalontology-4.0.0.jar exactly as the pom
# describes it, without needing Maven: compile <sourceDirectory>src</> and
# copy the <resources> block (src/main/resources/schema/*.schema.json) into
# the class output, then jar it up.
#
#   sh build_jar.sh          # build
#   sh build_jar.sh --list   # build, then list the jar's contents
set -e
cd "$(dirname "$0")"

VERSION=4.0.0
JAR=target/causalontology-$VERSION.jar

rm -rf target/classes
mkdir -p target/classes target
javac -d target/classes $(find src -name '*.java')
cp -R src/main/resources/. target/classes/
jar --create --file "$JAR" -C target/classes .
echo "built $JAR"

# The conformance runner, recompiled on its own against the finished jar and
# left OUTSIDE it, in target/test-classes. An installed-mode run puts that
# directory ahead of the installed jar on the classpath: the runner is then
# repository code (so it can still find the frozen vectors, exactly as the
# Python and JavaScript harnesses do), while every binding class it exercises
# - SchemaValidator above all - is resolved from the artifact. That is what
# "binding under test" reports, and what the repo-path guard checks.
rm -rf target/test-classes
mkdir -p target/test-classes
javac -cp "$JAR" -d target/test-classes src/org/causalontology/Conformance.java
echo "built target/test-classes (conformance runner, for installed-mode runs)"

if [ "$1" = "--list" ]; then
    jar --list --file "$JAR"
fi
