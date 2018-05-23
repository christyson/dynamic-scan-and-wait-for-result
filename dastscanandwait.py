from __future__ import print_function
import argparse
import sys
import subprocess
import time
from datetime import datetime


# helpers
def get_substring(s, leader, trailer):
    end_of_leader = s.index(leader) + len(leader)
    start_of_trailer = s.index(trailer, end_of_leader)
    return s[end_of_leader:start_of_trailer]


def now():
    return datetime.now().strftime('[%y.%m.%d %H:%M:%S] ')


def printunbuff(string):
    print(string,flush=True)


# args
parser = argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument('apiwrapperjar', help='File path to Veracode API Java wrapper')
parser.add_argument('appname', help='Name of the app to check in quotes if spaces')
parser.add_argument('vid', help='Veracode API credentials ID')
parser.add_argument('vkey', help='Veracode API credentials key')
parser.add_argument('-f','--flawonly', action="store_true", help='Peform a flaw only rescan')
parser.add_argument('-b', '--breakthebuild', action="store_true", help='Exit code non-zero if scan does not pass policy')
parser.add_argument('-wi', '--waitinterval', type=int, default=120, help='Time interval in seconds between scan policy status checks, default = 120s')
parser.add_argument('-wm', '--waitmax', type=int, default=3600, help='Maximum time in seconds to wait for scan to complete, default = 3600s')
args, unparsed = parser.parse_known_args()

# setup
base_command = ['java', '-jar', args.apiwrapperjar, '-vid', args.vid, '-vkey', args.vkey]

# uploadandscan wrapper action
if args.flawonly:
   command = base_command + ['-action', 'CreateAndSubmitDynamicRescan'] + ['-appname', args.appname] + ['-flawonly=True']
   printunbuff(now() + 'Running command: ' + ' '.join(['java', '-jar', args.apiwrapperjar, '-vid', args.vid[:6] + '...', '-vkey', '*****', '-action', 'CreateAndSubmitDynamicRescan','-appname', args.appname, '-flawonly=True'] + unparsed))
else:
   command = base_command + ['-action', 'CreateAndSubmitDynamicRescan'] + ['-appname', args.appname]
   printunbuff(now() + 'Running command: ' + ' '.join(['java', '-jar', args.apiwrapperjar, '-vid', args.vid[:6] + '...', '-vkey', '*****', '-action', 'CreateAndSubmitDynamicRescan' + '-appname' + args.appname], unparsed))
#printunbuff(command)

upload = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
printunbuff(upload.stdout.decode())

if upload.returncode == 0:
    try:
        app_id = get_substring(upload.stdout.decode(), 'appid=', ')')
		#java -jar VeracodeJavaAPI.jar -action GetBuildList -appid=226964 -vid 60b65a5ec9f60bb758637efc39d782ed -vkey 7832e
		# D:\CheckSelected>java -jar VeracodeJavaAPI.jar -action GetBuildInfo -appid=226964 -buildid=1787204 -vid 60b65a5ec9f60bb758637efc39d782ed -vkey 
        command = base_command + ['-action', 'GetBuildList'] + ['-appid=', app_id]
#       printunbuff(now() + 'Running command: ' + ' '.join(['java', '-jar', args.apiwrapperjar, '-vid', args.vid[:6] + '...', '-vkey', '*****', '-action', 'GetBuildList'+ ' app_id=' + app_id] + unparsed))
        getbuildlist = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
#       printunbuff(getbuildlist.stdout.decode())
        builds = getbuildlist.stdout.decode()
        number_of_builds = builds.count('build_id')
#       print('Number of builds: ' +str(number_of_builds))
        if (number_of_builds == 0):
           print("No policy builds found")
        count = 0
 #      printunbuff('number of builds is: ' + str(number_of_builds))
        for build in builds.splitlines():
           if build.find != "":
              if build.find('build_id="') != -1:
                 count = count + 1
                 if (count == number_of_builds):
                    build_id = get_substring(build, 'build_id="', '"')
                    printunbuff('Build Id is ' + build_id)
#        build_id = get_substring(upload.stdout.decode(), 'Dynamic Rescan request submitted for application ID - "', '"')
    except ValueError as e:
        printunbuff(e)
        sys.exit(1)

    # watch scan status for policy pass/fail
    if args.breakthebuild:
        command = base_command + ['-action', 'GetBuildInfo', '-appid', app_id, '-buildid', build_id]

        wait_so_far = 0
        while wait_so_far <= args.waitmax:
            time.sleep(args.waitinterval)
            build_info = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            printunbuff(now() + 'Checking scan status [' + str(wait_so_far // args.waitinterval) + '/' + str(args.waitmax // args.waitinterval) + ']')

            if 'results_ready="true"' in build_info.stdout.decode():
                # Wait for policy compliance calculation to complete
                while True:
                    policy_compliance_status = get_substring(build_info.stdout.decode(), 'policy_compliance_status="', '"')
                    if policy_compliance_status not in ['Calculating...', 'Not Assessed']:
                        printunbuff(now() + 'Scan complete, policy compliance status: ' + policy_compliance_status)
                        if policy_compliance_status in ['Conditional Pass', 'Pass']:
                            sys.exit(0)
                        else:
                            sys.exit(1)
                    else:
                        time.sleep(args.waitinterval)
                        build_info = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        printunbuff(now() + 'Scan complete, checking policy status')
            else:
                wait_so_far += args.waitinterval

        printunbuff(now() + 'Scan did not complete within maximum wait time.')
        sys.exit(1)
else:
    sys.exit(upload.returncode)
