#!/bin/bash

if [ $# -ne 1 ]; then
	echo "usage: ./new-database.bash db" >&2
	exit 1
fi

dir=$(git rev-parse --show-toplevel)/sql/migrations
cat $(find $dir -type f ! -name ".*" | sort) | sqlite3 -bail $1
