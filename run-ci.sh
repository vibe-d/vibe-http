#!/bin/bash

set -e -x -o pipefail

DUB_ARGS="--build-mode=${DUB_BUILD_MODE:-separate} ${DUB_ARGS:-}"
# default to run all parts
: ${PARTS:=lint,builds,unittests,examples,tests}

# force selecting vibe-core 2.x.x
if [[ $PARTS =~ (^|,)vibe-core-1(,|$) ]]; then
    RECIPES=`find | grep dub.sdl`
    sed -i "s/\"vibe-core\" version=\">=1\.0\.0 <3\.0\.0-0\"/\"vibe-core\" version=\">=1.0.0 <2.0.0-0\"/g" $RECIPES
fi

if [[ $PARTS =~ (^|,)lint(,|$) ]]; then
    ./scripts/test_version.sh
    # Check for trailing whitespace"
    grep -nrI --include=*.d '\s$'  && (echo "Trailing whitespace found"; exit 1)
fi

if [[ $PARTS =~ (^|,)builds(,|$) ]]; then
    # test for successful release build
    dub build --combined -b release --compiler=$DC
    dub clean --all-packages

    # test for successful 32-bit build
    if [ "$DC" == "dmd" ]; then
        dub build --combined --arch=x86
        dub clean --all-packages
    fi
fi

if [[ $PARTS =~ (^|,)unittests(,|$) ]]; then
    dub test --compiler=$DC $DUB_ARGS
    dub clean --all-packages
fi

if [[ $PARTS =~ (^|,)examples(,|$) ]]; then
    for ex in $(\ls -1 examples/); do
        echo "[INFO] Building example $ex"
        (cd examples/$ex && dub build --compiler=$DC $DUB_ARGS && dub clean)
    done
fi

if [[ $PARTS =~ (^|,)tests(,|$) ]]; then
    for ex in `\ls -1 tests/`; do
        if ! [[ $PARTS =~ (^|,)redis(,|$) ]] && [ $ex == "redis" ]; then
            continue
        fi
        if [ -r tests/$ex/run.sh ]; then
            echo "[INFO] Running test $ex"
            (cd tests/$ex && ./run.sh)
        elif [ -r tests/$ex/dub.json ] || [ -r tests/$ex/dub.sdl ]; then
            if [ $ex == "vibe.http.client.2080" ]; then
                echo "[WARNING] Skipping test $ex due to TravisCI incompatibility".
            else
                echo "[INFO] Running test $ex"
                (cd tests/$ex && dub --compiler=$DC $DUB_ARGS && dub clean)
            fi
        fi
    done
fi
