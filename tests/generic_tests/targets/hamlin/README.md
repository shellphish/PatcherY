# AIxCC Hamlin Edition
This version of Hamlin has been modified to work with the AIxCC pipeline.
The main changes are the following:

* added a run.sh script which applies patches, builds, and allows running the program in the AIxCC format
* updated the source Makefile to use clang, with `-g` and `-fsanitize=address`

## Running
Like all AIxCC challenges, just use the `run.sh` located in the root of the `challenge` dir.
