@echo off
call :GET_CURRENT_DIR
cd %THIS_DIR%
IF NOT EXIST "%APPDATA%"\ZcashParams (
MKDIR "%APPDATA%"\ZcashParams
)
FOR %%F IN (sapling-spend.params, sapling-output.params, sprout-groth16.params) DO (
    IF NOT EXIST "%APPDATA%"\ZcashParams\%%F  (
        ECHO Downloading Zcash trusted setup %%F, this may take a while ...
	        compat\curl-7.68.0-win64-mingw\bin\curl.exe --output "%APPDATA%"\ZcashParams\%%F -# -L -C - https://z.cash/downloads/%%F
    )
)
goto :EOF
:GET_CURRENT_DIR
pushd %~dp0
set THIS_DIR=%CD%
popd
goto :EOF