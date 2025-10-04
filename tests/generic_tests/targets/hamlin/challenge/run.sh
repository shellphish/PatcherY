#!/bin/bash

#
# Based on the original AIxCC run.sh script
#

# get directory containing the script
SCRIPT_DIR="$(dirname $(realpath $0))"
SRC="${SCRIPT_DIR}/src"

warn() {
    echo "$*" >&2
}

# kill the script with an error message
die() {
    warn "$*"
    exit 1
}

print_usage() {
    warn "A helper script for CP interactions."
    warn
    warn "Usage: ${SCRIPT_FILE} pull_source|build|run_pov|run_test"
    warn
    warn "Subcommands:"
    warn "  pull_source                         Pull the CP source code into the src/ directory; will overwrite existing source"
    warn "  build [<patch_file> <source>]       Build the CP (an optional patch file for a given source repo can be supplied)"
    warn "  run_pov <blob_file> <harness_id>    Run the binary data blob against specified harness"
    warn "  run_tests                           Run functionality tests"
    die
}

## execute commands
CMD_NAME=$1
shift
case ${CMD_NAME,,} in
    "build")
        ##### Run patch command if patch file was supplied #####

        if [ -n "$1" ]; then
            PATCH_FILE=$1
            SOURCE_TARGET="./src"

            if [ ! -d "${SRC}/${SOURCE_TARGET}" ]; then
                echo "Source repository not found: ${SRC}/${SOURCE_TARGET}"
                echo "Valid source names: ${CP_SOURCE_NAMES[*]}"
            fi

            # check validity of patch file provided
            PATCH_FILE=$(realpath "${PATCH_FILE}")
            [[ -f "${PATCH_FILE}" ]] || die "Patch file not found: ${PATCH_FILE}"

            # apply patch
            # shellcheck disable=SC2086
            git -C "${SRC}/${SOURCE_TARGET}" apply \
                ${PATCH_EXTRA_ARGS} \
                "${PATCH_FILE}" || die "Patching failed using: ${PATCH_FILE}"
        fi

	(
		cd src/ && \
		make clean && \
		make -j8 && \
		cp build/hamlin.bin $SCRIPT_DIR/
	)

        ;;

    "run")
        ##### Run based on a blob #####
        IN_FILE=$1
        BIN_FILE="$SCRIPT_DIR/hamlin.bin"

        export CHESS=1
        output=$($BIN_FILE < $IN_FILE 2>&1)
        echo "$output"
        if echo "$output" | grep -q "ERROR: AddressSanitizer"; then
          exit 37
        fi
        exit 0
        ;;
    *)
        echo "Invalid command $CMD_NAME"
        print_usage
        ;;
esac
