# BASHTHS
BASH - Threat Hunting Script
Threat Hunting Script Installation Guide
Installation
1. Included files:
1.1. Threat hunting script: tth-stilil91347.sh
1.2. Detached signature: tth-stilil91347.sh.sig
1.3. Installation PDF: stilil91347.pdf
2. Installation:
2.1. Start with verifying the script using the command
2.1.1. gpg –verify tth-stilil91347.sh.sig tth-stilil91347.sh
2.1.2. If the signature passes, move on to the next point.
2.2. Place the script in the folder /opt/security/
2.2.1. The script is set up so that it will check which directory it is running from and if it
is not within the /opt/security directory, the script will exit.
2.2.2. Next, within the /opt/security directory there has to be a directory named
“working”. I.e., /opt/security/working. The directory has to exist and it has to be
writable or else the script will exit.
3. Script Running Requirements:
3.1. In order to run the script manually there are three positional arguments needed. These
are to be passed through the CLI at script initiation. In the format below:
3.2. ./tth-stilil91347.sh <Argument 1> <Argument 2> <Argument 3>
3.3. These three positional arguments are:
3.3.1. Argument 1: The server URLfor downloading the IOC-file – This has to be a
HTTPS URL
3.3.2. Argument 2: This needs to be the upload-server address, in an SSH setting this
would be the address that goes after the @ – I.e.,
<identity>@<upload-server-address>
3.3.3. Argument 2: This needs to be your identity. Which will fit into the user-id part of
the ssh-statement.
3.3.4. If any of these arguments are wrong or missing, this will cause the script to exit.4. Script Functionality:
4.1. Ensure that the script has execution privileges
4.1.1. chmod +x tth-stilil91347.sh
4.2. The script will take in the three arguments, specified above.
4.3. It will then check the download-server URL protocol.
4.4. If pt. 4.2 passes, the script will download an IOC-file and a signature file.
4.4.1. The IOC-file will be verified with the signature file
4.4.2. Next, the IOC-file’s date will be verified.
4.4.3. If the two checks passes, the script will resume executing
4.5. The script’s validation happens through two static-binaries of grep and sha256sum,
these tools will be installed on the system in the respective directories
/opt/security/validate and /opt/security/strcheck.
4.5.1. These tools need to be validated to ensure that they are legitimate and
uncorrupted.
4.5.2. This will happen with sha256-hashes provided in the IOC-file.
4.5.3. If they both pass, the script will resume executing.
4.5.4. Up to this point, if any of these checks fail, the script will stop executing. From
this point forward, the errors/warnings/info-statements will log every task the
script completes.
4.6. The script will now read through the IOC-file, extract the provided Indicators of
Compromise and search the system for matches, either in the form of provided
strings/regular expressions or file-hashes.
4.6.1. If any match is found, an output will inform about the finding and the details will
be appended to the end-report.
4.6.2. The details will be found under the heading “IOC Matches” in this format:
IOC/STR HASHVALUE path/filename
4.7. Next, the program will do some basic data gathering on the state of the system.
4.7.1. First, the system’s listening ports
4.7.2. Then the firewall rules
4.7.3. It will then find all the installed files in the sbin folder and validate the packages
against the dpkg MD5 hash database to see if there are any corrupted files.
4.7.4. The next task will entail searching through specified folders for files that have
been created within the past 48 hours as well as any S/GUID files regardless of
creation time.4.7.5. Lastly it will check the permissions of two vulnerable folders. If the folders do not
exist, the script will pre-emptively create these folders and then set the
permissions as advised.
4.8. After all these tasks have been completed, the script will take all the gathered
information and append them to a log file called “iocreport.txt”. This report will be, with
all the other automatically generated files, archived into a file and then uploaded to the
server, with the data provided in argument 2 and 3 (see: 3.3.2 & 3.3.3).
4.8.1. It is then validated, and a sha256 hash is generated in a text file called
checksum.sha256
4.8.2. And a detached signature file will be generated for validation.
4.8.3. After the three files have been successfully uploaded, the program will SSH into
the server, and validate the archive using the provided signature.
4.9. Before termination, the script will tidy up its working environment and delete all files
generated during its runtime.
5. Automating the script
5.1. Edit the user’s crontab, typing in:
5.1.1. sudo crontab -e
5.2. Add a cron job line:
5.2.1. The format is: minute hour day-of-month month day-of-month <command>
5.3. To run the script at 2 AM every day as root enter:
5.3.1. 0 2 * * * /opt/security/tth-stilil91347.sh <arg1> <arg2> <arg3> – the arguments
are the same as if run manually.
5.3.2. Save and exit the editor.
6. Troubleshooting
6.1. The script will have a minimal output in the CLI when run, this output will indicate either
OK or FAILED.
6.2. In case of terminal failure, the generated file “script.log” will contain a more detailed
output of the error. This log will be written up to the point of successful signature
verification on the upload-server. In case there are errors. The log appended to the
report will contain detailed information up to the point of archiving.
6.2.1. In the case of terminal failure, the script will exit and the files will remain in the
/opt/security/working folder for auditing.
