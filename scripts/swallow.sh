#!/bin/bash

set -e

src="git@github.com:klihub/refkit-ostree-upgrade.git"
dst=$(realpath ./files/refkit-ostree)

while [ "${1#-}" != "$1" -a -n "$1" ]; do
    case $1 in
        --source|--src|-s)
            src="$2"
            shift 2
            ;;
        --destination|--dst|-d)
            src="$2"
            shift 2
            ;;
        --dry-run|-n)
            xeq=echo
            shift
            ;;
        --help|-h)
            echo "usage: $0 [--dry-run] [--src <git-uri>] [--dst <dir>]"
            exit 0
            ;;
        *)
            echo "unknown option/argument: $1"
            echo "usage: $0 [--dry-run] [--src <git-uri>] [--dst <dir>]"
            exit 1
            ;;
    esac
done

if [ ! -d $dst ]; then
    echo "missing destination directory $dst"
    exit 1
fi

stamp=$(date +%Y-%m-%d-%H%M)
echo "Saving previous version as $dst.$stamp..."
$xeq mv $dst $dst.$stamp
$xeq mkdir -p $dst
$xeq cd $dst/..
$xeq git clone $src ${dst##*/}
$xeq cd -
