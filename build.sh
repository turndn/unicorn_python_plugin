#! /bin/bash
gcc -nostdlib sample_rop.s
objdump -d a.out | grep '^ ' | cut -f2 | perl -pe 's/(\w{2})\s+/\\x\1/g'
