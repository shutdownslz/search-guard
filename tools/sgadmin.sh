#!/bin/bash
SCRIPT_PATH="${BASH_SOURCE[0]}"
if [ -L $SCRIPT_PATH ]; then
    if ! [ -x "$(command -v realpath)" ]; then
        #we fallback to readlink
        DIR="$( cd "$( dirname $(readlink "$SCRIPT_PATH") )" && pwd )"
    else
        DIR="$( cd "$( dirname "$(realpath "$SCRIPT_PATH")" )" && pwd )"
    fi
else
    DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
fi

BIN_PATH="java"

if [ -z "$JAVA_HOME" ]; then
    echo "WARNING: JAVA_HOME not set, will use $(which $BIN_PATH)"
else
    BIN_PATH="$JAVA_HOME/bin/java"
fi

"$BIN_PATH" $JAVA_OPTS -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "$DIR/../*:$DIR/../../../lib/*:$DIR/../deps/*" com.floragunn.searchguard.tools.SearchGuardAdmin "$@" 2>/dev/null

