#!/usr/bin/env python2
import os, sys, argparse, random, urllib, glob, tarfile, time, re, fnmatch, gzip

# Create empty objects to contain warnings and errors
error_list = []

# Set up the argument parser
parser = argparse.ArgumentParser(description="Parser for SoftNAS support reports")
parser.add_argument("--caseid", help="Required: Kayako ticket or case-id")
parser.add_argument("--url", help="Required: Download url for the support report")
args = parser.parse_args()
if args.caseid is None:
    parser.print_help()
    parser.exit()
if args.url is None:
    parser.print_help()
    parser.exit()

# Some functions
def get_role():
    if os.path.exists(replication_config):
        if "Role" in open(replication_config).read():
            with open(replication_config, 'r') as f:
                config_lines = f.readlines()
                for line in config_lines:
                    if "Role" in line:
                        role = re.search('"(.*?)"', line)
                        role = role.group(0).replace('"','')
        else:
            role = "Unknown"
    else:
        role = "Single"
    return role


# Make a random word dictionary
word_file = "/usr/share/dict/words"
words = open(word_file).read().splitlines()
fname = random.choice(words)

# Check for the local working directory
home = os.getenv("HOME")
local_path = home + "/support-reports/" + args.caseid + "/" + fname
if os.path.exists(local_path) == False:
    os.makedirs(local_path, 0777)
    print "Created local path %s \n" % (local_path)
else:
    print "Duplicate path exists"
    sys.exit(1)

# Download the support report
url = args.url
file_name = '%s/sr-%s.tgz' % (local_path, fname)
print "Downloading %s \n" % (file_name)
urllib.urlretrieve (url, file_name)

# Untar the support report
sr = tarfile.open(file_name)
print "Extracting %s \n" % (file_name)
sr.extractall(local_path)
sr.close()

# Decide if this is a source or target node
replication_config = local_path + "/var/www/softnas/config/snaprepstatus.ini"

role = get_role()
print "This server role is %s\n" % (role)
new_path = home + "/support-reports/" + args.caseid + "/" + role
if os.path.exists(new_path):
    c_time = os.path.getmtime(new_path)
    t_stamp = time.strftime('_%Y-%m-%d-%H%M%S', time.localtime(c_time))
    a_name = new_path + t_stamp
    print "Renaming %s to %s \n" % (new_path, a_name)
    os.rename(new_path, a_name)
    print "Renaming %s to %s \n" % (local_path, new_path)
    os.rename(local_path, new_path)
else:
    print "Renaming %s to %s \n" % (local_path, new_path)
    os.rename(local_path, new_path)

# Change into the new working directory
os.chdir(new_path)

# Get the software version
ver_file = 'var/www/softnas/version'
if os.path.exists(ver_file):
    with open(ver_file, 'r') as version_log:
        version = version_log.readlines()
    version_log.close()
    for ver in version:
        print "SoftNAS version is %s" % (ver)
else:
    ver_result = "No softnas version file found"
    print "Error : %s" % ver_result
    error_list.append(ver_result)

# Get dir list from the support report
dirs = glob.glob("*")

# Get the working dirs based on regex
statsPattern = "stats.*"
tmpPattern = "tmp"
varPattern = "var"
for dir in dirs:
    if fnmatch.fnmatch(dir, statsPattern):
        statsDir = dir
    if fnmatch.fnmatch(dir, tmpPattern):
        tmpDir = dir
    if fnmatch.fnmatch(dir, varPattern):
        varDir = dir
sysLogs = varDir + "/log"
appLogs = varDir + "/www/softnas/logs"
appConfig = varDir + "/www/softnas/config"


## Parse the stats directory
os.chdir(statsDir)

# iostat : Check out the CPU stats
with open('./iostat') as file:
    contents = file.readlines()
    cpu_count = contents[0].split()[5:]
    cpus = ' '.join(cpu_count)
    print "CPU count: %s" % cpus

# free : Check out the memory stats
with open('./free', 'r') as file:
     contents = file.readlines()
     mem_stats = contents[1].split()
     swap_stats = contents[3].split()
     mem_total = mem_stats[1]
     mem_used = mem_stats[2]
     mem_free = mem_stats[3]
     swap_used = swap_stats[2]

print "Memory stats: %sMB Total, %sMB Used, %sMB Free, %sMB Swap used" % (mem_total, mem_used, mem_free, swap_used)

if int(swap_used) > 1:
    result = "ERROR: System is swapping, %sMB Swap used" % (swap_used)
    error_list.append(result)

if int(swap_used) == 0:
    result = "PASS: System is not swapping, %sMB Swap used" % (swap_used)
    print result + "\n"


# Check root volumes to see if its above 80% full
# Treat VMWare different becase the df log is different
print "Checking root volume capacity"
with open('./df-h', 'r') as file:
    lv_flag = "vg_softnas-lv_root"
    for line in file.readlines()[1:2]:
        if lv_flag in line:
            print "This is VMWARE lvm"
            file.close()
            with open('./df-h', 'r') as file:
                for line in file.readlines()[2:3]:
                    mount = "/"
                    size = line.split()[0]
                    usage = float(line.split()[3].strip(' \t\n\r%'))
                    file.close()

            if usage > 80:
                result = "%s usage is %d %%; over the 80 %% threshold\n" % (mount,usage)
                print "\n%s" % (result)
                error_list.append(result)
            else:
                print "Mount point %s is %s %% full\n" % (mount,usage)

        else:
            with open('./df-h', 'r') as file:
                for line in file.readlines()[1:2]:
                    mount = line.split()[5]
                    size = line.split()[1]
                    usage = float(line.split()[4].strip(' \t\n\r%'))
                    file.close()

            if usage > 80:
                result = "%s usage is %d %%; over the 80 %% threshold\n" % (mount,usage)
                print "\n%s" % (result)
                error_list.append(result)
            else:
                print "Mount point %s is %s %% full\n" % (mount,usage)




# Check the root-history file to see if software was modified
print "Checking root-history"
flagged_words = ['install', 'yum', 'rpm', 'pip']
flagged_lines = []
if os.path.exists('./history-root'):
    with open('./history-root', 'r') as file:
        contents = file.readlines()
    for line in contents:
        if any(i.lower() in line.lower() for i in flagged_words):
            flagged_lines.append(line)

    if len(flagged_lines) > 0:
        result = "Found modifications in root-history"
        error_list.append(result)
        error_list.append(flagged_lines)
        print result + "\n"

    if len(flagged_lines) == 0:
        result = "PASS: No flagged lines in root-history"
        print result


# ifconfig : Look for interface errors
with open('./ifconfig', 'r') as file:
    lines = file.read().strip()

    if_devs = lines.split('\n\n')

    for dev in if_devs:
        try:
            ifstat_list = []

            iferror_count = 0

            if_stat = dev.split('\n')
            stat = map(str.strip, if_stat)

            if_name = stat[0].split()[0]

            if len(if_name) > 0:
                ifstat_list.append(if_name)
            else:
                pass

            if_addr = stat[1].split()[1]

            if len(if_addr) > 0:
                ifstat_list.append(if_addr)
            else:
                pass

            rXerrors = "rX" + stat[4].split()[2]

            if len(if_addr) > 0:
                ifstat_list.append(rXerrors)
                count = rXerrors.split(':')[1]
                if count != "0":
                    iferror_count += 1
                    error_list.append([if_name, rXerrors])
                else:
                    pass

            rXdropped = "rX" + stat[4].split()[3]

            if len(rXdropped) > 0:
                ifstat_list.append(rXdropped)
                count = rXdropped.split(':')[1]
                if count != "0":
                    iferror_count += 1
                    error_list.append([if_name, rXdropped])
                else:
                    pass

            rXoverruns = "rX" + stat[4].split()[4]

            if len(rXoverruns) > 0:
                ifstat_list.append(rXoverruns)
                count = rXoverruns.split(':')[1]
                if count != "0":
                    iferror_count += 1
                    error_list.append([if_name, rXoverruns])
                else:
                    pass

            tXerrors = "tX" + stat[5].split()[2]

            if len(tXerrors) > 0:
                ifstat_list.append(tXerrors)
                count = tXerrors.split(':')[1]
                if count != "0":
                    iferror_count += 1
                    error_list.append([if_name, tXerrors])
                else:
                    pass

            tXdropped = "tX" + stat[5].split()[3]

            if len(tXdropped) > 0:
                ifstat_list.append(tXdropped)
                count = tXdropped.split(':')[1]
                if count != "0":
                    iferror_count += 1
                    error_list.append([if_name, tXdropped])
                else:
                    pass

            tXoverruns = "tX" + stat[5].split()[4]

            if len(tXoverruns) > 0:
                ifstat_list.append(tXoverruns)
                count = tXoverruns.split(':')[1]
                if count != "0":
                    iferror_count += 1
                    error_list.append([if_name, tXoverruns])
                else:
                    pass

            tXcarrier = "tX" + stat[5].split()[5]

            if len(tXcarrier) > 0:
                ifstat_list.append(tXcarrier)
                count = tXcarrier.split(':')[1]
                if count != "0":
                    iferror_count += 1
                    error_list.append([if_name, tXcarrier])
                else:
                    pass

            tXcollision = "tX" + stat[6].split()[0]

            if len(tXcollision) > 0:
                ifstat_list.append(tXcollision)
                count = tXcollision.split(':')[1]
                if count != "0":
                    iferror_count += 1
                    error_list.append([if_name, tXcollision])
                else:
                    pass

            if iferror_count > 0:
                print "ERROR: Found %d interface errors on device %s" % (iferror_count, if_name)
            else:
                print "PASS: Found %d interface errors on device %s" % (iferror_count, if_name)


            print ifstat_list
            # print '\n'

        except:
            pass

# lsblk : get some disk info
disk_devices = []
invalid_disks = ['fd0', 'zd0', 'zd16', 'zd32', 'sdtier']
with open('./lsblk', 'r') as file:
    contents = file.read().splitlines()
for line in contents:
    if not any(i in line for i in invalid_disks) and 'disk' in line:
        disk_devices.append(line)

disk_devices = sorted(disk_devices)
print "Instance has %d attached disk devices" % (len(disk_devices))
for dev in disk_devices:
    print dev
print '\n'


# netstat : look at the tcp connections
with open('./netstat', 'r') as file:
    contents = file.read().splitlines()
tcp_list = []
established = []
listen = []
time_wait = []
fin_wait = []

for line in contents:
    if 'tcp' in line:
        tcp_list.append(line)

for item in tcp_list:
    if 'ESTABLISHED' in item:
        established.append(item)

    if 'LISTEN' in item:
        listen.append(item)

    if 'TIME_WAIT' in item:
        time_wait.append(item)

    if 'FIN_WAIT' in item:
        fin_wait.append(item)

print "Total number TCP sockets is %d" % len(tcp_list)
print "Total number 'ESTABLISHED' is %d" % len(established)
print "Total number 'LISTEN' is %d" % len(listen)
print "Total number 'TIME_WAIT' is %d" % len(time_wait)
print "Total number 'FIN_WAIT' is %d" % len(fin_wait)

## Parse the zfs info file for pool errors
os.chdir(new_path)
os.chdir(tmpDir)

# Get a list of zfs-errors
print "\nLooking for zfs pool errors"
zpool_zip_files = glob.glob('zfs-info.????.status.gz')

for file in zpool_zip_files:
    input = gzip.GzipFile(file, 'rb')
    s = input.read()
    input.close()

    of = file.replace(".gz", "")
    output = open(of, 'wb')
    output.write(s)
    output.close()

    os.remove(file)

zpool_status_files = glob.glob('zfs-info.????.status')
flags = ['pool:', 'errors:']
pool_errors = []

for file in zpool_status_files:
    with open(file) as search:
        for line in search:
            line = line.strip()
            if any(i.lower() in line.lower() for i in flags):
                if 'pool' in line:
                    pool_name = line.split()[1]
                if 'errors' in line:
                    err_status = line.split(':')[1].strip()
                    print "Error status for %s is %s" % (pool_name, err_status)
                    if err_status != "No known data errors":
                        pool_errors.append([pool_name, err_status])
                        error_list.append(pool_errors)

## Parse the files /var/log
os.chdir(new_path)
os.chdir(sysLogs)
print "\nPocessing files in %s" % (sysLogs)

# unzip the compressed files
sys_zip_files = glob.glob("*.gz")
print "Unzipping compressed files\n"

for file in sys_zip_files:
    input = gzip.GzipFile(file, 'rb')
    s = input.read()
    input.close()

    of = file.replace(".gz", "")
    output = open(of, 'wb')
    output.write(s)
    output.close()

    os.remove(file)

# Parse old messages files
print "Processing messages"
message_files = glob.glob("messages-*")
flagged_messages = ['error', 'panic', 'timeout', 'reset', 'zed', 'tainted' 'zfs', 'oom', 'checksum', 'fail', 'zio', 'retry', 'Deleting interface']
exclude_lines = ['dev fd0', 'floppy:', 'print_req_error', 'initialized', 'pcieport', 'BAR 13:']
message_errors = []
boot_count = []
message_err_log = new_path + "/%s-messages_err.log" % args.caseid
boot_count_log = new_path + "/%s-boot_count.log" % args.caseid

message_files.sort()

if len(message_files) > 0:
    for file in message_files:
        with open(file, 'r') as message:
            contents = message.readlines()
            for line in contents:
                if any(i.lower() in line.lower() for i in flagged_messages) and not any(i.lower() in line.lower() for i in exclude_lines):
                    message_errors.append([file, line])
                if 'Booting SMP configuration' in line:
                    boot_count.append([file, line])

message_errors.sort()

# Parse latest messages and append
file = "messages"
with open(file, 'r') as latest_messages:
    contents = latest_messages.readlines()
    for line in contents:
        if any(i.lower() in line.lower() for i in flagged_messages) and not any(i.lower() in line.lower() for i in exclude_lines):
            message_errors.append([file, line])
        if 'Booting SMP configuration' in line:
            boot_count.append(line)

    with open(message_err_log, 'w') as err_log:
        for error in message_errors:
            err_log.write("%s\n" % error)
    err_log.close()

    with open(boot_count_log, 'w') as boot_log:
        for boot_message in boot_count:
            boot_log.write("%s\n" % boot_message)
    boot_log.close()


if len(message_errors) > 0:
    message_result = "Found %s matches in combined message logs" % len(message_errors)
    error_list.append(message_result)
    print "%s\n" % message_result
else:
    print "No errors found in messages\n"



# Parse old monit logs
print "Processing monit logs"
monit_files = glob.glob("monit.log-*")
flagged_alerts = ['error']
exclude = 'There is no service by that name'
monit_errors = []
monit_err_log = new_path + "/%s-monit_err.log" % args.caseid

if len(monit_files) > 0:
    monit_files.sort()

    for file in monit_files:
        with open(file, 'r') as alert_file:
            contents = alert_file.readlines()
            for line in contents:
                if exclude not in line and any(i.lower() in line.lower() for i in flagged_alerts):
                    monit_errors.append([file, line])

# Parse latest monit log and append
file = "monit.log"
with open(file, 'r') as latest_alerts:
    contents = latest_alerts.readlines()
    for line in contents:
        if exclude not in line and any(i.lower() in line.lower() for i in flagged_alerts):
            monit_errors.append([file, line])

    with open(monit_err_log, 'w') as err_log:
        for error in monit_errors:
            err_log.write("%s\n" % error)
    err_log.close()


if len(monit_errors) > 0:
    monit_result = "Found %s matches in combined monit logs" % len(monit_errors)
    error_list.append(monit_result)
    print "%s\n" % monit_result
else:
    print "No errors found in monit logs\n"


## Parse the files in /var/www/softnas/logs
os.chdir(new_path)
os.chdir(appLogs)
print "Processing files in %s\n" % os.getcwd()

# unzip the compressed files
app_zip_files = glob.glob("*.gz")
print "Unzipping compressed files\n"

for file in app_zip_files:
    input = gzip.GzipFile(file, 'rb')
    s = input.read()
    input.close()

    of = file.replace(".gz", "")
    output = open(of, 'wb')
    output.write(s)
    output.close()

    os.remove(file)


# Look for any btier errors
btier_err_log = new_path + "/%s-btier_err.log" % args.caseid
if os.path.isfile('btier.log'):
    print "Looking for btier errors"
    btier_errors = []
    btier_flags = ['error', 'fail']
    with open('btier.log', 'r') as btier_log:
        contents = btier_log.readlines()
        for line in contents:
            if any(i.lower() in line.lower() for i in btier_flags):
                btier_errors.append(line)

        if len(btier_errors) > 0:
            btier_status = "Found %s matches in btier logs" % len(btier_errors)
            error_list.append(btier_status)
            with open(btier_err_log, 'w') as err_log:
                for error in btier_errors:
                    err_log.write("%s\n" % error)
            err_log.close()
            print "%s\n" % btier_status
        else:
            print "No errors in found Btiers log\n"


# Look for deltasync errors
deltasync_err_log = new_path + "/%s-deltasync_err.log" % args.caseid
if os.path.isfile('deltasync.log'):
    print "Looking for deltasync errors"
    deltasync_errors = []
    deltasync_flags = ['error', 'fail']
    with open('deltasync.log', 'r') as deltasync_log:
        contents = deltasync_log.readlines()
        for line in contents:
            if any(i.lower() in line.lower() for i in deltasync_flags):
                deltasync_errors.append(line)

        if len(deltasync_errors) > 0:
            deltasync_status = "Found %s matches in deltasync logs" % len(deltasync_errors)
            error_list.append(deltasync_status)
            with open(deltasync_err_log, 'w') as err_log:
                for error in deltasync_errors:
                    err_log.write("%s\n" % error)
            err_log.close()
            print "%s\n" % deltasync_status
        else:
            print "No errors in found deltasync log\n"



# Parse old flexfiles logs
flexfiles_err_log = new_path + "/%s-flexfiles_err.log" % args.caseid
if os.path.isfile('flexfiles.log'):
    print "Processing flexfiles logs"
    flex_logs = glob.glob("flexfiles.log-*")
    flex_alerts = ['error', 'fail']
    flex_errors = []

    if len(flex_logs) > 0:
        flex_logs.sort()
        for file in flex_logs:
            with open(file, 'r') as flex_log:
                contents = flex_log.readlines()
                for line in contents:
                    if any(i.lower() in line.lower() for i in flex_alerts):
                        flex_errors.append([file, line])
            flex_log.close()


# Parse latest flexfiles log and append
    file = "flexfiles.log"
    with open(file, 'r') as flex_log:
        contents = flex_log.readlines()
        for line in contents:
            if any(i.lower() in line.lower() for i in flex_alerts):
                flex_errors.append([file, line])
    flex_log.close()

    if len(flex_errors) > 0:
        flex_status = "Found %s errors in flexfiles log\n" % len(flex_errors)
        error_list.append(flex_status)
        with open(flexfiles_err_log, 'w') as err_log:
            for error in flex_errors:
                err_log.write("%s\n" % error)
        err_log.close()
        print "%s\n" % flex_status

    else:
        print "No errors found in flexfiles logs\n"


# Parse old license logs
license_err_log = new_path + "/%s-license_err.log" % args.caseid
if os.path.isfile('license.log'):
    print "Processing license logs"
    license_logs = glob.glob("license.log-*")
    license_alerts = ['error', 'fail']
    license_errors = []

    if len(license_logs) > 0:
        license_logs.sort()

        for file in license_logs:
            with open(file, 'r') as license_log:
                contents = license_log.readlines()
                for line in contents:
                    if any(i.lower() in line.lower() for i in license_alerts):
                        license_errors.append([file, line])
            license_log.close()


# Parse latest license log and append
    file = "license.log"
    with open(file, 'r') as license_log:
        contents = license_log.readlines()
        for line in contents:
            if any(i.lower() in line.lower() for i in license_alerts):
                license_errors.append([file, line])
    license_log.close()

    if len(license_errors) > 0:
        license_status = "Found %s errors in license logs" % len(license_errors)
        error_list.append(license_status)
        with open(license_err_log, 'w') as err_log:
            for error in license_errors:
                err_log.write("%s\n" % error)
        err_log.close()
        print "%s\n" % license_status

    else:
        print "No errors found in license logs\n"

# Parse the progress logs
prog_logs = glob.glob("progress-*")
if len(prog_logs) > 0:
    prog_err_log = new_path + "/%s-progress_err.log" % args.caseid
    print "Parsing the volume progress logs"
    prog_alerts = ['error', 'fail']
    prog_errors = []

    prog_logs.sort()

    for file in prog_logs:
        with open(file, 'r') as prog_log:
            contents = prog_log.readlines()
            for line in contents:
                if any(i.lower() in line.lower() for i in prog_alerts):
                    prog_errors.append([file, line])
        prog_log.close()

    if len(prog_errors) > 0:
            prog_status = "Found %s errors in replication progress logs" % len(prog_errors)
            error_list.append(prog_status)
            with open(prog_err_log, 'w') as err_log:
                for error in prog_errors:
                    err_log.write("%s\n" % error)
            err_log.close()
            print "%s\n" % prog_status

    else:
            print "No errors found in replication progress logs\n"


# Parse old snapreplicate logs
if os.path.isfile('snapreplicate.log'):
    snap_err_log = new_path + "/%s-snaprep_err.log" % args.caseid
    print "Processing snapreplicate logs"
    snaprep_logs = glob.glob("snapreplicate.log-*")
    snaprep_alerts = ['error', 'fail', 'retry', 'heartbeat', 'takeover']
    snaprep_errors = []

    if len(snaprep_logs)> 0:
        snaprep_logs.sort()

        for file in snaprep_logs:
            with open(file, 'r') as snaprep_log:
                contents = snaprep_log.readlines()
                for line in contents:
                    if any(i.lower() in line.lower() for i in snaprep_alerts):
                        snaprep_errors.append([file, line])
            snaprep_log.close()


# Parse latest snapreplicate log and append
    file = 'snapreplicate.log'
    with open(file, 'r') as snaprep_log:
        contents = snaprep_log.readlines()
        for line in contents:
            if any(i.lower() in line.lower() for i in snaprep_alerts):
                snaprep_errors.append([file, line])
    snaprep_log.close()

    if len(snaprep_errors) > 0:
        snaprep_status = "Found %s errors in snapreplicate logs" % len(snaprep_errors)
        error_list.append(snaprep_status)
        with open(snap_err_log, 'w') as err_log:
                for error in snaprep_errors:
                    err_log.write("%s\n" % error)
        err_log.close()
        print "%s\n" % snaprep_status

    else:
        print "No errors found in snapreplicate logs\n"


# Parse old snserv logs
if os.path.isfile('snserv.log'):
    snserv_err_log = new_path + "/%s-snserv_err.log" % args.caseid
    print "Processing snserv logs"
    snserv_logs = glob.glob("snserv.log-*")
    snserv_alerts = ['error', 'fail', 'retry', 'heartbeat', 'takeover']
    snserv_errors = []

    if len(snserv_logs) > 0:
        snserv_logs.sort()

        for file in snserv_logs:
            with open(file, 'r') as snserv_log:
                contents = snserv_log.readlines()
                for line in contents:
                    if any(i.lower() in line.lower() for i in snserv_alerts):
                        snserv_errors.append([file, line])
            snserv_log.close()


# Parse latest snserv log and append
    file = 'snserv.log'
    with open(file, 'r') as snserv_log:
        contents = snserv_log.readlines()
        for line in contents:
            if any(i.lower() in line.lower() for i in snserv_alerts):
                snserv_errors.append([file, line])
    snserv_log.close()

    if len(snserv_errors) > 0:
        snserv_status = "Found %s errors in snserv logs" % len(snserv_errors)
        error_list.append(snserv_status)
        with open(snserv_err_log, 'w') as err_log:
                for error in snserv_errors:
                    err_log.write("%s\n" % error)
        err_log.close()
        print "%s\n" % snserv_status

    else:
        print "No errors found in snserv logs"


print "Log Summary:\n"
if len(boot_count) > 0:
    print "WARNING: Found %s reboot messages" % len(boot_count)

if len(error_list) > 0:
    print "\n"
    for error in error_list:
        print "WARNING: %s" % error
else:
    print "Nothing found in error list"
