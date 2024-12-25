#!/bin/bash

set -e -x -o pipefail

DUB_ARGS="--build-mode=${DUB_BUILD_MODE:-separate} ${DUB_ARGS:-}"
# default to run all parts
: ${PARTS:=lint,builds,unittests,examples,tests}

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

    # test for successful notls build
    if [ "$DC" == "dmd" ]; then
        dub build --override-config vibe-stream:tls/notls
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

if [[ $PARTS =~ (^|,)vibe-d(,|$) ]]; then
    PATH_ESCAPED=$(echo `pwd` | sed 's_/_\\/_g')
    SED_EXPR='s/"vibe-http": [^,]*(,?)/"vibe-http": \{"path": "'$PATH_ESCAPED'"\}\1/g'

    git clone https://github.com/vibe-d/vibe.d.git --depth 1
    cd vibe.d
    dub upgrade -s
    for i in `find | grep dub.selections.json`; do
        sed -i -E "$SED_EXPR" $i
    done
    dub test :mongodb $DUB_ARGS
    dub test :redis $DUB_ARGS
    dub test :web $DUB_ARGS
    cd ..
fi

