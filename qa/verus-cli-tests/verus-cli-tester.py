from subprocess import call, Popen, PIPE, check_output
from time import sleep
from os import environ, path

cli_path = path.join(environ["CI_PROJECT_DIR"], "verus-cli")
seconds = 300
startdaemon = path.join(cli_path, "verusd")
cli_cmds = "verus getmininginfo", "verus getwalletinfo", "verus stop"
verusd = Popen(startdaemon, shell=True, close_fds=True)
sleep(seconds)
for cmd in cli_cmds:  # type: str
    path.join(cli_path, cmd)
    with open("log.txt", "a") as log:
        log.write(check_output(cmd, shell=True))
