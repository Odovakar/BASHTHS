#! /bin/bash

# Working Directories
SCRIPT_RES_DIR="/opt/security"
SCRIPT_ROOT_DIR="/opt/security"
WORKING_DIR="/opt/security/working/"

VALIDATE="/opt/security/bin/validate"
STRCHECK="/opt/security/bin/strcheck"

DATE="$(date +"%Y%m%d")"
TIMESTAMP=$(date +"%Y%m%d-%H:%M")
IOC_FILE_NAME="IOC-$DATE.ioc"
GPG_FILENAME="IOC-$DATE.gpg"

##########################################################################################################################################
#----------------------------------------------- Utilities & Initial Requirement Checks -------------------------------------------------#
##########################################################################################################################################

# S8 - Error Handling
# Takes three arguments, which is the type of message (INFO, ERROR, WARNING), has a smaller stdout footprint, and a longer more detailed message for the log.
logs_and_messages () {
    local log_type="$1"
    local log_message="$2"
    local stdout_message="$3"
    local hostname=$(hostname)

    message="$log_type-$hostname $TIMESTAMP: $log_message" >> script.log
    echo "$message" >> script.log
    if [[ -n $stdout_message ]]; then
        echo -e "$stdout_message"
    fi
}

# Does some manipulation to the URL before sending it to check for https response
process_ioc_url () {
    local provided_url="$1"
    local lower_case_ioc_url="${provided_url,,}"

    # Checks for absence of http or https in the ioc download string, and adds if necessary
    if [[ ! "$lower_case_ioc_url" =~ ^(https://|http://) ]]; then
        lower_case_ioc_url="https://$lower_case_ioc_url"
        logs_and_messages "INFO" "Added https:// to the URL."
    fi

    # If the ioc download string explicitly contains http:// swap it with https://
    if [[ "$lower_case_ioc_url" =~ ^http:// ]]; then
        lower_case_ioc_url="${lower_case_ioc_url/http:\/\//https:\/\/}"
        logs_and_messages "INFO" "Changed http:// to https://"
    fi
    check_for_https_protocol $lower_case_ioc_url
}

# Using wget to check the URL protocol without downloading anything
check_for_https_protocol () {
    processed_ioc_url="$1"

    wget --spider -q "$processed_ioc_url"
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "The URL protocol is HTTPS." "URL protocol check: OK"
    else
        logs_and_messages "WARNING" "The URL protocol is not HTTPS. Non-HTTPS connections are less secure and may be vulnerable to man-in-the-middle attacks." "URL protocol check: FAILED"
        exit 1
    fi
}

# Brief output-explanation of what arguments needs to be provided and in which order
how_to_use() {
    echo "Usage: $0 <parameter1> <parameter2> <parameter3>"
    echo "  <parameter1>: Needs to be an HTTPS URL directing to IOC download server."
    echo "  <parameter2>: Needs to be the URL to the server where the output logs are to be uploaded."
    echo "  <parameter2>: Your identity."
}

##########################################################################################################################################
#---------------------------------------- S1 Use the working directory of /opt/security/working -----------------------------------------#
##########################################################################################################################################

# Checks if the script is in the correct folder before executing further, and if the working directory exists before executing further.
check_pwd_and_dir_existence() {
    # Check if in /opt/security/
    if [[ $PWD != "$SCRIPT_ROOT_DIR" ]]; then
        logs_and_messages "ERROR" "Script must be run from the $SCRIPT_ROOT_DIR directory, exiting script. Check if the folder exists and/or is writable." "Script must be run from the $SCRIPT_ROOT_DIR directory, exiting script. Check if the folder exists and/or is writable."
        exit 1
    fi

    # Checks existence and permissions of the working dir of /opt/security/working and changes directory if everything works.
    if [ -d "$WORKING_DIR" ]; then
        check_dir_permissions "$WORKING_DIR" #$MOCK_NOT_WRITABLE_DIR
        cd "$WORKING_DIR"
    else
        logs_and_messages "ERROR" "The $WORKING_DIR directory does not exist, exiting script." "$WORKING_DIR existence check: FAILED"
        exit 1
    fi
}

##########################################################################################################################################
#------------------------------------------------- S2 Ensure the directory is writable --------------------------------------------------#
##########################################################################################################################################

# Checks if the working directory is writable
check_dir_permissions () { 
    if [[ -w "$WORKING_DIR" ]]; then
        logs_and_messages "INFO" "The $WORKING_DIR directory is writable." "$WORKING_DIR permissions: OK"
    else
        logs_and_messages "ERROR" "The $WORKING_DIR is not writable, exiting script." "The $WORKING_DIR is not writable, exiting script."
        exit 1
    fi
}

##########################################################################################################################################
#------------------------------- S3 Download the daily IoC file from the URL specified on the command line ------------------------------#
##########################################################################################################################################

# Downloads the file containing the IOC-data
download_ioc_file () {
    wget -q --show-progress "$processed_ioc_url/$IOC_FILE_NAME"

    # If command fails, throw error and exit script.
    if [ $? -ne 0 ]; then 
        logs_and_messages "ERROR" "IOC-file download failed, exiting script. Please review the download URL." "IOC-file download failed, exiting script. Please review the download URL."
        exit 1
    fi

    # Checks existence of IOC file
    if [[ -e  "$IOC_FILE_NAME" ]]; then
        logs_and_messages "INFO" "$IOC_FILE_NAME successfully downloaded." "$IOC_FILE_NAME downloaded OK"
    else
        logs_and_messages "ERROR" "IOC-file does not exist, exiting script." "IOC-file does not exist, exiting script."
        exit 1
    fi
}

##########################################################################################################################################
#----------------------------------------------- S4 Validate the integrity of the IoC file ----------------------------------------------#
##########################################################################################################################################

# Downloads the detached gpg signature for verifying the IOC-file
download_gpg_signature () {
    wget -q --show-progress "$processed_ioc_url/$GPG_FILENAME"

    if [ $? -ne 0 ]; then
        logs_and_messages "ERROR" "Detached signature file-download failed, exiting script." "Detached signature file-download failed, exiting script."
        exit 1
    fi

    logs_and_messages "INFO" "GPG signature-file downloaded successfully." "GPG signature-file downloaded: OK"
}

# Verifies the IOC-file with the downloaded detached signature
verify_ioc_file () {
    # Checking IOC file integrity up against the downloaded signature.
    verify_result=$(gpg --verify "$GPG_FILENAME" "$IOC_FILE_NAME" 2>&1)
    clean_result=$(echo "$verify_result" | grep -i 'Good signature\|Primary key fingerprint\|BAD signature')

    # Cleans up the gpg response and checks if the signature was good/bad/or if it has a warning in order to reduce the output of the script
    if [[ "${clean_result,,}" =~ .*bad.* ]]; then
        logs_and_messages "ERROR" "$clean_result"
        logs_and_messages "ERROR" "Signature verification of the IOC file failed, exiting script." "Signature verification of the IOC-file failed, exiting script."
        exit 1
    elif [[ "${clean_result,,}" =~ .*good.* ]]; then
        logs_and_messages "INFO" "$clean_result" "IOC-file verification: OK"
    fi

    if [[ "${clean_result,,}" =~ .*warn.* ]]; then
        logs_and_messages "WARNING" $clean_result "Untrusted signature: WARNING"
    fi

    validate_ioc_file_date $DATE
}

##########################################################################################################################################
#-----------------------------------------  S5 Validate that the date-stamp in the file is correct. -------------------------------------#
##########################################################################################################################################

# Check that the date-today and the date in the IOC-file is the same
validate_ioc_file_date () {
    if [[ $(awk "NR==2" "$IOC_FILE_NAME" | grep "$DATE") == "$DATE" ]]; then
        logs_and_messages "INFO" "The date today and the date of the IOC file matches." "IOC-file date match: OK"
    else
        logs_and_messages "ERROR" "Date stamp in IOC file and current date do not match, exiting script." "Date stamp in IOC file and current date do not match, exiting script."
        exit 1
    fi
}

##########################################################################################################################################
#-------------------------  S6 Use the hashes provided to confirm that the validate and strcheck tools are correct. ---------------------#
##########################################################################################################################################

# Function that runs sha256sum
sha256sum_function () {
    sha256sum $1 | awk '{print $1}'
}

# Extract the tool's checksums for validation
extract_checksum () {
    grep --no-ignore-case $1 "$IOC_FILE_NAME" | awk '{print $2}'
}

# Runs the sha256 function on the tools and checks the hash-output up against what was provided in the IOC-file
validate_tools () {
    local tool_type="$1"
    local tool_path="$2"
    local calculated_hash
    local validation_hash

    # Extracting checksum from IOC-document
    validation_hash=$(extract_checksum "$tool_type")

    # Calculating tool hash
    calculated_hash=$(sha256sum_function "$tool_path")

    # If the hashes don't match, exit program
    if [[ "$validation_hash" != "$calculated_hash" ]]; then
        logs_and_messages "ERROR" "The $tool_type tool's hash does not match the provided hash, exiting script." "The $tool_type tool's hash check: FAILED"
        exit 1
    fi
    logs_and_messages "INFO" "The $tool_type tool has been validated." "$tool_type tool validation: OK"
}

##########################################################################################################################################
#------------------  S7 If the above items fail the script should generate an appropriate error message to STDOUT and exit --------------#
##########################################################################################################################################


##########################################################################################################################################
#--------------------------------------------------  S9 String and hash value searches --------------------------------------------------#
##########################################################################################################################################

# Extracts the str and hash IOCs from the downloaded file
extract_iocs_from_doc () {
    local ioc_file="$1"
    local search_term="$2"
    local VALIDATE="$3"
    local STRCHECK="$4"

    # For each instance of the provided search term (IOC/STR) checks the second and third strings of the line and stores in a variable
    $STRCHECK "$search_term" "$ioc_file" | while read -r line; do
        local ioc_value=$(echo "$line" | awk '{print $2}')
        local ioc_path=$(echo "$line" | awk '{print $3}')

        # Checks if the extracted IOC is a hash- or string-based IOC and passes the data to the search functions
        if [[ "$search_term" == "IOC" ]]; then
            logs_and_messages "INFO" "Now Searching $ioc_path."
            search_for_hashes $ioc_value "$ioc_path" "$VALIDATE" "$STRCHECK"

        elif [[ "$search_term" == "STR " ]]; then
            sanitized_ioc_str=$(echo "$ioc_value" | sed -E 's/^["\/]+|["\/]+$//g')
            logs_and_messages "INFO" "Now Searching $ioc_path."
            search_for_strings "$sanitized_ioc_str" "$ioc_path" "$STRCHECK"
        else
            logs_and_messages "ERROR" "Something went wrong when extracting the IOCs from the IOC-file." "IOC extraction: FAILED"
        fi
    done
}

# This function takes the hash-values from the ioc-file and check every file in the provided folder structure to a max depth of 2
search_for_hashes () {
    local search_command=$(find "$ioc_path" -maxdepth 2 -type f -print0 2>&1 | xargs -0 -P 4 $VALIDATE -b 2>&1 | $STRCHECK -F "$ioc_value" 2>&1 ) # \( -path /snap -o -path /proc -o -path /sys -o -path /run -o -path /var/cache -o -path /var/spool \) -prune -o 
    
    if [[ -d "$ioc_path" ]]; then
        if [[ "$search_command" ]]; then
            while read -r line; do
                file_path=$(echo "$line" | awk '{print $2}')
                logs_and_messages "INFO" "Found match for; $ioc_value in the $ioc_path folder structure, at this location $file_path." "IOC match found, appended to report: WARNING"
                echo "$search_term $ioc_value $file_path" >> iocmatches
            done <<< "$search_command"
        else
            logs_and_messages "INFO" "No findings for $ioc_value in the $ioc_path folder structure."
        fi
    else
        logs_and_messages "ERROR" "The $ioc_path directory does not exist on this system." "Directory existence check for the $ioc_path directory: FAILED"
    fi
}

# This function takes the strings from the IOC-file and checks all the files within the provided directory structure if there is any occurrence of that particular string
search_for_strings () {
    local search_command=$(find "$ioc_path" -type f -print0 2>&1 | xargs -0 -P 4 "$STRCHECK" -E "$ioc_value" 2>&1)
    if [[ -d "$ioc_path" ]]; then
        if [[ "$search_command" ]]; then
            while read -r line; do
                file_path=$(echo "$line" | sed 's/:.*$//')
                hash_value=$("$VALIDATE" "$file_path" | awk '{print $1}')
                logs_and_messages "INFO" "Found match for; $ioc_value in the $ioc_path folder structure, at this location $file_path, with the hash value of $hash_value." "IOC match found, appended to report: WARNING"
                echo "$search_term $hash_value $file_path" >> iocmatches
            done <<< "$search_command"
        else
            logs_and_messages "INFO" "No findings for $ioc_value in the $ioc_path folder structure."
        fi
    else
        logs_and_messages "ERROR" "The $ioc_path directory does not exist on this system." "Directory existence check for the $ioc_path directory: FAILED"
    fi
}

##########################################################################################################################################
#------------------  S10 Validate packages, report and log firewall, port, and file creation state, tweak permissions -------------------#
##########################################################################################################################################

# Logs the system's listening ports and creates a temporary document containing the info.
log_listening_ports () {
    echo "LISTENING PORTS" > listeningports
    local output=$(netstat -tuln | $STRCHECK -i "LISTEN" >> listeningports)
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "Listening ports summary have been logged and will be appended to report." "Listening ports check: OK"
    else
        logs_and_messages "ERROR" "Failed to retrieve the listening ports summary" "Listening ports check: FAILED"
    fi
}

# Reads the firewall rules and creates a temporary document containing the info.
log_firewall_rules () {
    echo "FIREWALL RULES" > firewall
    local output=$(iptables -nL >> firewall)
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "Firewall rules have been logged and will be appended to report." "Firewall rules check: OK"
    else
        logs_and_messages "ERROR" "Retrieving firewall rules have failed." "Firewall rules check: FAILED"
    fi
}

# TODO SJEKK OM DETTE TRENGER NOE LOGGFØRING
validate_sbin_package_files () {
    # Making a temporary file with all the packages that are usually/potentially installed in sbin
    cat /var/lib/dpkg/info/*.md5sums | $STRCHECK -E "/sbin" | awk '{print $2}' | sed 's/.*\///' > sbintemp
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "Creating a temporary file for the MD5 sums of the packages within the sbin directory successful." "Package MD5 sum retrieval: OK"
    else
        logs_and_messages "ERROR" "Retrieving info on potentially installed packages within the sbin directory failed" "Package MD5 sum retrieval: FAILED"
    fi

    # Getting the packages that are currently installed on the system
    dpkg --get-selections | awk '{print $1}' > installedpackages
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "Retrieving info on potentially installed packages within the sbin directory retrieved." "Package info retrieval: OK"
    else
        logs_and_messages "ERROR" "Retrieving info on potentially installed packages within the sbin directory failed" "Package info retrieval: FAILED"
    fi
    # Checking the currently installed packages up against the potentially installed packages and porting them to a temp file.
    "$STRCHECK" -Fxf installedpackages sbintemp > sbininstalled
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "Checking the potentially installed packages versus the actually installed packages was successful." "Installed package comparison: OK"
    else
        logs_and_messages "ERROR" "Comparing the potentially installed packages versus the installed packages failed" "Installed package comparison: FAILED"
    fi


    # Checking the MD5 hash of the currently installed packages in the sbin directory
    if [[ -e "$PWD/sbininstalled" ]]; then
        while read -r line; do
            # Only log failures (stderr) to binfailure
            debsums "$line" 2>&1 | "$STRCHECK" -E "FAILED|error" >> binfailure
        done < "$PWD/sbininstalled"
    fi
}

report_changed_files () {
    # Checking for changed files within the /var/www folder structure that might have occured the past 48 hours.
    find /var/www -mtime -2 -type f -print > changedfiles
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "Checking the files within the /var/www folder for files created within the last 48 hours successful" "48 hour file-creation check: OK"
    else
        logs_and_messages "ERROR" "Checking the files within the /var/www folder for files created within the last 48 hours successful" "48 hour file-creation check: FAILED"
    fi
    find /var/www -type f \( -perm -4000 -o -perm -2000 \) -print >> changedfiles
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "Checking the files within the /var/www folder for SUID and GUID files successful" "S/GUID file creation check: OK"
    else
        logs_and_messages "ERROR" "Checking the files within the /var/www folder for SUID and GUID files failed" "S/GUID file creation check: FAILED"
    fi
}

set_permissions_in_www_dir () {
    local directory="$1"
    
    # Checking if the directory exists, if not. The script will create the folder in order to pre-emptively set safer permissions on it
    if [[ ! -d "$directory" ]]; then
        mkdir $directory
        logs_and_messages "INFO" "Created $directory in /var/www/" "Missing directory in /var/www created: OK"
    fi

    # If the folder has executable permissions, change them to r-w -> 666 for everyone.
    if [[ -x $directory ]]; then
        local current_permissions="$(stat -c %A $directory)"
        logs_and_messages "WARNING" "The permissions on $directory were set to: $current_permissions" "Current $directory permissions $current_permissions gives users/attackers execution rights: WARNING"
        chmod 666 -R $directory
        local new_permissions="$(stat -c %A $directory)"
        logs_and_messages "INFO" "The permissions on $directory have been changed to $new_permissions" "Changed the $directory permissions to $new_permissions: OK"
        echo "$TIMESTAMP The current permissions on $directory were: $current_permissions, the permissions have been changed to changed to $new_permissions." >> wwwpermissions
    fi
}

##########################################################################################################################################
#-----------------------------------------  S11 Create report, archive, sign, and upload files ------------------------------------------#
##########################################################################################################################################

generate_report () {
    if [[ -e "$PWD/iocmatches" ]]; then
        echo -e "IOC MATCHES\n" >> iocreport.txt
        cat "iocmatches" >> iocreport.txt
        echo "" >> iocreport.txt
        cat "listeningports" >> iocreport.txt
        echo "" >> iocreport.txt
        cat "firewall" >> iocreport.txt
        echo "" >> iocreport.txt
        echo "Failed Binary File Hash Scans" >> iocreport.txt
        cat "binfailure" >> iocreport.txt
        echo "" >> iocreport.txt
        echo "Permissions on Directories in the /var/www Folder Structure" >> iocreport.txt
        cat "wwwpermissions" >> iocreport.txt
        echo "" >> iocreport.txt
        echo "Script Log" >> iocreport.txt
        cat "script.log" >> iocreport.txt
    fi
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "Final report creation successful" "Final report generation: OK"
    else
        logs_and_messages "ERROR" "Final report creation failed" "S/GUID file creation check: FAILED"
    fi
}

compress_and_archive_files () {
    local hostname=$(hostname)

    filename="$hostname-tth-$DATE.tgz"

    tar -czvf "$filename" * > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "Archive compression successful" "Archive compression: OK"
    else
        logs_and_messages "ERROR" "Archive compression failed" "Archive compression: FAILED"
        exit 1
    fi
    
    generate_detached_signature "$filename"

}

generate_detached_signature () {

    $VALIDATE "$filename" >> checksum.sha256
    gpg --local-user tht2024@tht.noroff.no --output "$filename".sig --detach-sig "$filename"

    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "Detached signature generation successful" "Detached signature generation: OK"
    else
        logs_and_messages "ERROR" "Detached signature generation failed" "Detached signature generation: FAILED"
        exit 1
    fi
}

upload_files_via_rsync () {
    local hostname=$(hostname)
    local location_string="/submission/"$hostname"/"$(date +%Y)"/"$(date +%m)""
    local ssh_identity="$(cat /opt/security/$USER_ID.id)"

    rsync -avz -e "ssh -i $ssh_identity" "$hostname"-tth-"$DATE".tgz checksum.sha256 "$hostname"-tth-$DATE.tgz.sig "$USER_ID"@"$UPLOAD_SERVER":/submission/"$hostname"/"$(date +%Y)"/"$(date +%m)"
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "SSH upload via rsync successful" "rsync upload: OK"
    else
        logs_and_messages "ERROR" "SSH upload via rsync failed" "rsync upload: FAILED"
        exit 1
    fi
    ssh_into_server_and_validate_upload "$USER_ID" "$UPLOAD_SERVER" "$location_string" "$hostname"
}

##########################################################################################################################################
#-----------------------------------------------  S12 SSH into server and validate files ------------------------------------------------#
##########################################################################################################################################

# Connects to server via SSH and executes file validation of the newly uploaded files
ssh_into_server_and_validate_upload () {
    hostname_string="$4"
    local temp_file=$(temp_script_for_upload_validation "$location_string" "$hostname_string" "$DATE")
    local ssh_identity="$(cat /opt/security/$USER_ID.id)"

    ssh -i "$ssh_identity" "$USER_ID"@"$UPLOAD_SERVER" < $temp_file
    if [ $? -eq 0 ]; then
        logs_and_messages "INFO" "SSH upload via rsync successful" "rsync upload: OK"
    else
        logs_and_messages "ERROR" "SSH upload via rsync failed" "rsync upload: FAILED"
        exit 1
    fi
}

##########################################################################################################################################
#----------------------------  S13 When complete, the script reports the name and size of the upload (in MB) ----------------------------#
##########################################################################################################################################

# Generates a script that is ran on the upload-server in order to validate the uploaded archive.
temp_script_for_upload_validation () {
  echo 'hostname_string='$2'' > temp_validation_script.sh
  echo 'cd /submission/'$2'/$(date +%Y)/$(date +%m)' >> temp_validation_script.sh
  echo 'gpg --verify '$2'-tth-'$3'.tgz.sig '$2'-tth-'$3'.tgz 2>/dev/null' >> temp_validation_script.sh
  echo 'if [ $? -ne 0 ]; then' >> temp_validation_script.sh
  echo '    echo "$(date +"%Y%m%d-%H:%M") Bad signature on uploaded archive."' >> temp_validation_script.sh
  echo 'else' >> temp_validation_script.sh
  echo '    echo "Remote system signature validation: OK"' >> temp_validation_script.sh
  echo 'fi' >> temp_validation_script.sh >> temp_validation_script.sh
  echo 'size_bytes=$(stat -c%s "'$2'-tth-'$3'.tgz")' >> temp_validation_script.sh
  echo 'size_mb=$(echo "scale=4; $size_bytes / 1024 / 1024" | bc)' >> temp_validation_script.sh
  echo 'echo "Uploaded file size: $size_mb"MB' >> temp_validation_script.sh
  echo 'echo "TTH IoC Check '$2': OK"' >> temp_validation_script.sh
  chmod +x temp_validation_script.sh
  echo temp_validation_script.sh  # Return the temporary script path
}

##########################################################################################################################################
#---------------------------------------------------  S16 Tidying up the environment ----------------------------------------------------#
##########################################################################################################################################

cleaning_up_the_environment () {
    rm -r "$WORKING_DIR"*
    if [ $? -eq 0 ]; then
        echo "Environment cleanup: OK"
    fi
}

main () {
    local HTTPS_URL="$1"
    local UPLOAD_SERVER="$2"
    local USER_ID="$3"
    
    if [[ "$#" -lt 3 ]]; then
        how_to_use
        exit 1
    fi

    # Initial Requirements 
    #check_positional_arguments "$1" "$2" "$3"
    process_ioc_url "$HTTPS_URL"
    check_pwd_and_dir_existence

    # Download and Setup of processes
    #download_import_pubkey
    download_gpg_signature "$GPG_FILENAME" "$DATE"
    download_ioc_file "$IOC_FILE_NAME" "$DATE"
    verify_ioc_file "$DATE" "$GPG_FILENAME" "$IOC_FILE_NAME"

    # Validating the static binary tools.
    validate_tools "VALIDATE" "$VALIDATE"
    validate_tools "STRCHECK" "$STRCHECK"

    # Extract IOCs
    # NOTE: Since there's a lot of variables being passed into nested functions, the order will always be the same as the order set within the function below (see: declaration of variables at the top of the function)
    extract_iocs_from_doc "$IOC_FILE_NAME" "IOC" "$VALIDATE" "$STRCHECK"
    extract_iocs_from_doc "$IOC_FILE_NAME" "STR " "$VALIDATE" "$STRCHECK"

    # General State Information Gathering for End Report.
    log_listening_ports "$STRCHECK"
    log_firewall_rules
    validate_sbin_package_files "$STRCHECK"
    report_changed_files
    set_permissions_in_www_dir "/var/www/uploads"
    set_permissions_in_www_dir "/var/www/images"

    # wrap-up
    generate_report
    compress_and_archive_files
    upload_files_via_rsync "$UPLOAD_SERVER" "$USER_ID"

    cleaning_up_the_environment
}

# Call main function
main "$@" # Passing all variables to the main function

exit 0