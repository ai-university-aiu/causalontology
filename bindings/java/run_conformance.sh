#!/bin/sh
# Repo-mode conformance run: compile the sources here and run the runner
# against them. Set CAUSALONTOLOGY_TEST_INSTALLED and put a built jar on the
# classpath instead to exercise a real consumer's view (see build_jar.sh).
set -e
cd "$(dirname "$0")"
mkdir -p out
javac -d out $(find src -name '*.java')
# Maven's process-resources step, by hand: the bundled schemas must be on the
# classpath so the runner's drift guard actually compares them.
cp -R src/main/resources/. out/
java -cp out org.causalontology.Conformance
