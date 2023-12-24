#!/bin/bash

ls -alh | cut -d ' ' -f 15 | cut -d '.' -f 1 > control_list.txt