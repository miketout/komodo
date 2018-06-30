from subprocess import Popen, check_output
from time import sleep
from os import environ, path

seconds = 300
startdaemon = path.join(environ["CI_PROJECT_DIR"], "verusd")
cli_cmds = "verus getmininginfo", "verus getwalletinfo", "verus stop"
verusd = Popen(startdaemon, shell=True, close_fds=True)
sleep(seconds)
for cmd in cli_cmds:  # type: str
    cmd = path.join(environ["CI_PROJECT_DIR"], cmd)
    with open(path.join(environ["CI_PROJECT_DIR"], "log.txt"), "a") as log:
        log.write(check_output(cmd, shell=True))
