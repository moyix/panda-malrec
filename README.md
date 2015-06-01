panda-malrec
============

A system to record malware using [PANDA](http://github.com/moyix/panda).

This is the system currently used by
http://panda.gtisc.gatech.edu/malrec/

Usage
-----

This system processes executables and runs them in PANDA. The basic
workflow takes samples from `queue/pending`, passes them off to the
`runmal.py`, which eventually deposits them in `queue/finished`. It also
writes a stamp in `logs/stamps`. At this point, The logs are compressed
using `rrpack.py` from [PANDA](http://github.com/moyix/panda).

I use a fairly low-tech approach to managing this parallel queue that
relies on `inotifywait` and GNU `parallel`. To detect new samples and
run them, I use:

    while true; do ls queue/pending/ | parallel -j 4 python scripts/runmal.py conf/malrec.config {/} {%} ; sleep 600 ; done

And to detect when PANDA has finished recording and pack the logs:

    inotifywait -q -m -r -e MOVED_TO -e CLOSE_WRITE --format %w%f logs/stamps/ | parallel -u -j 4 scripts/pack.sh logs/rr/{/}

Most of the configuration lives in [`malrec.config`](conf/malrec.config),
but I haven't been great about making sure everything references that,
so there are quite a few absolute paths hanging around in various
scripts. Beware!

Once per day, I also generate movies from the replays, and check the
sample IDs with VirusTotal. These periodic tasks are managed by
`cron`. My crontab looks like:

    30 22 * * * /home/brendan/malrec/scripts/fillqueue.sh
    00,10,20,30,40,50 * * * * /home/brendan/malrec/scripts/genindex.sh
    00 4 * * * /home/brendan/malrec/scripts/vtlookup.py /home/brendan/malrec/conf/malrec.config
    00 4 * * * /home/brendan/malrec/scripts/movies.sh

Samples become available once per day. The `genindex.sh` just builds the
(very ugly) web page every 10 minutes.

GUI Analysis
------------

In order for the GUI analysis and actuation to work, you will need to
use this branch of PANDA:

https://github.com/moyix/panda/tree/wip/unsafememaccess

And then symlink the `pmemaddressspace.py` script into Volatility's
`volatility/plugins/addrspaces` subdirectory.

Note that you will get poor results unless you disable mouse
acceleration in the guest VMs.

Disclaimer
----------

This is not intended to work for anyone else out of the box, just to
provide a starting point. You will undoubtedly have to make heavy local
modifications. That said, if you want to make it more general and
contribute improvements back, please feel free!
