#!/bin/bash

FLAGS=$1
COMMENT=$2

if [[ $COMMENT == "10M" ]]; then
    COMMENT="10 flows * 1M"

elif [[ $COMMENT == "100M" ]]; then
    COMMENT="100 flows * 1M"
elif [[ $COMMENT == "100Q" ]]; then
    COMMENT="10 flows * 10M"

elif [[ $COMMENT == "1000M" ]]; then
    COMMENT="1000 flows * 1M"
elif [[ $COMMENT == "1000Q" ]]; then
    COMMENT="100 flows * 10M"
elif [[ $COMMENT == "1000T" ]]; then
    COMMENT="10 flows * 100M"

elif [[ $COMMENT == "10000M" ]]; then  # Infeasible
    COMMENT="10000 flows * 1M"
elif [[ $COMMENT == "10000Q" ]]; then
    COMMENT="1000 flows * 10M"
elif [[ $COMMENT == "10000T" ]]; then
    COMMENT="100 flows * 100M"
fi

python3 src/main.py -i br-fc2518b3193b -m SC -f monitor -d auto -x $FLAGS -c "$COMMENT" >/dev/null &

sleep 2

# Get pid of the last process
PID=$!

taskset -cp 0 $PID

delay=1

trap cleanup EXIT

function cleanup() {
    echo "Cleaning up"
    verify_file_size
    kill $PID
}

function verify_file_size() {
    oldcount=0
    count=$(cat "data/in/"* | wc -l)
    issues=1

    while [[ $issues -lt 2 ]]; do
        if [[ $count -eq $oldcount ]]; then
            issues=$((issues+1))
        else
            issues=1
        fi
        oldcount=$count
        count=$(cat "data/in/"* | wc -l)
        echo "count: $count, issues: $issues, oldcount: $oldcount"
        if [[ $issues -eq 2 ]]; then
            echo "Detected no output for 2 consecutive seconds"
            break
        fi

        sleep $delay
    done

}

top -b -d $delay -p $PID | awk -v FLAGS="$FLAGS" -v COMMENT="$COMMENT" -v OFS="," '$1+0>0 {
print FLAGS,COMMENT,$1,$6,$9; fflush() }' >> data/in/memoryusage.csv
