VerusCoin Command Line Tools v0.5.0

Contents:
verusd - VerusCoin's enhanced Komodo daemon
komodo-cli - VerusCoin's Komodo command line utility
verus - wrapper for komodo-cli that applies the command to the VRSC coin
verusd.sh - wrapper for komodod that sets the VerusCoin parameters to defaults properly

The first time on a new system you will need to run ./fetch-params before using komodod or verusd.

Run ./verusd to launch komodod, and use verus to run commands such as:
./verus stop
Which signals komodod (if it is running) to stop running.
