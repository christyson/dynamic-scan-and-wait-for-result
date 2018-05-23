    usage: dastscanandwait.py [-h] [-b] [-wi WAITINTERVAL] [-wm WAITMAX] apiwrapperjar vid vkey

    A Python wrapper to the Veracode Java API jar, providing dynamic scan "break the build" functionality

    positional arguments:
      apiwrapperjar         File path to Veracode API Java wrapper
	  appname               Name of the Veracode application profile to check in quotes if spaces
      vid                   Veracode API credentials ID
      vkey                  Veracode API credentials key
    
    optional arguments:
      -h, --help            show this help message and exit
      -f                    if present do a flaw only rescan.  Remove for a full scan     
	  -b, --breakthebuild   Exit code non-zero if scan does not pass policy
      -wi WAITINTERVAL, --waitinterval WAITINTERVAL
                            Time interval in seconds between scan policy status
                            checks, default = 60s
      -wm WAITMAX, --waitmax WAITMAX
                            Maximum time in seconds to wait for scan to complete,
                            default = 3600s

    Any additional arguments will be passed through to the API jar.
	
Note: A word document explains how to integrate this with Jenkins