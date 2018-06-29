from subprocess import call, Popen, PIPE, check_output
import time
sleep = 300
startdaemon = 'verusd'
cli_cmds = "verus getmininginfo", "verus getwalletinfo", "verus stop"
verusd = Popen(startdaemon, shell=True, close_fds=True)
time.sleep(sleep)
for cmd in cli_cmds:  # type: str
    with open ("log.txt", "a") as g:
        g.write(check_output(cmd, shell=True))