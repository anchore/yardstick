#!/usr/bin/env bash

ERROR="\033[1;31m"
SUCCESS="\033[1;32m"
TITLE="\033[1;35m"
RESET="\033[0m"

i=0

temp_files=()

function run() {
    tmp_file=$(mktemp /tmp/yardstick-test.XXXXXX)
    temp_files+=( $tmp_file )
    echo -e "${TITLE}$i| Running $@${RESET}"
    $@ | tee $tmp_file
    rc=${PIPESTATUS[0]}
    if [ $rc -eq 0 ]; then
        echo -e "${SUCCESS}Success${RESET}"
    else
        echo -e "${ERROR}Exited with $rc${RESET}"
        exit 1
    fi
    ((i++))
}

function last_output_file() {
    echo ${temp_files[${#temp_files[@]} - 1]}
}

function last_output() {
    cat $(last_output_file)
}

function assert_last_output_length() {
    expected=$1
    len=$(last_output | wc -l | tr -d ' ')
    if [[ "$len" == "$expected" ]]; then
        return
    fi
    echo -e "${ERROR}Unexpected length $len != $expected${RESET}"
    exit 1
}

function assert_last_output_contains() {
    target=$1
    is_in_file=$(cat $(last_output_file) | grep -c "$target")
    if [ $is_in_file -eq 0 ]; then
        echo -e "${ERROR}Target not found in contents '$target'${RESET}"
        echo -e "${ERROR}...contents:\n$(last_output)${RESET}"
        exit 1
    fi
}

run yardstick result clear

run yardstick result capture -r test

run yardstick result list -r test

assert_last_output_length 3
assert_last_output_contains "grype@v0.27.0"
assert_last_output_contains "grype@v0.72.0"
assert_last_output_contains "syft@v0.54.0"
assert_last_output_contains "docker.io/anchore/test_images:java-56d52bc@sha256:10008791acbc5866de04108746a02a0c4029ce3a4400a9b3dad45d7f2245f9da"

run yardstick result compare $(yardstick result list -r test --ids -t grype)

assert_last_output_contains "grype-v0.72.0-only"
assert_last_output_contains "commons-collections"
assert_last_output_contains "dom4j"
assert_last_output_contains "log4j"
assert_last_output_contains "spring-core"

run yardstick label apply $(yardstick result list -r test --ids -t grype@v0.72.0)

assert_last_output_contains "label: TruePositive"

ID_TO_REMOVE=$(yardstick label add -i foo -c CVE-1234-ASDF -p test-package -v 1.2.3 -n "testing" --label TP)
run yardstick label remove ${ID_TO_REMOVE}
assert_last_output_contains ${ID_TO_REMOVE}

echo "cleaning up temp files created:"
for i in ${!temp_files[@]}; do
  echo "   " ${temp_files[$i]}
  rm ${temp_files[$i]}
done


echo -e "\n${SUCCESS}PASS${RESET}"
