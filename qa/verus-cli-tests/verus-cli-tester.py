from subprocess import call, Popen, PIPE, check_output
from time import sleep

seconds = 300
startdaemon = "verusd"
cli_cmds = "verus getmininginfo", "verus getwalletinfo", "verus stop"
verusd = Popen(startdaemon, shell=True, close_fds=True)
sleep(seconds)
for cmd in cli_cmds:  # type: str
    with open("log.txt", "a") as log:
        log.write(check_output(cmd, shell=True))
