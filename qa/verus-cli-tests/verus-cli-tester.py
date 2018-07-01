from subprocess import Popen, check_output
from time import sleep
from os import environ, path

Popen("fetch-params", shell=True)
seconds = 600
cli_cmds = ["verus getblockchaininfo", "verus getmininginfo", "verus getwalletinfo", "verus stop"]
verusd = Popen("verusd", shell=True, close_fds=True)
sleep(seconds)
for cmd in cli_cmds:  # type: str
    with open(path.join(environ["CI_PROJECT_DIR"], "log.txt"), "a") as log:
        log.write("{0}\n".format(check_output(cmd, shell=True)))
