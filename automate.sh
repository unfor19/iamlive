#!/bin/bash

### Requirements --------------------------------------------------------------
# jq 1.6+
# bash 5.0+
# AWS CLI v2 (haven't tested with v1)
### ---------------------------------------------------------------------------

### Required Environment Variables --------------------------------------------
# Supports `.env` file
# IAMLIVE_ADMIN_AWS_ACCESS_KEY_ID       For updating IAM Policy
# IAMLIVE_ADMIN_AWS_SECRET_ACCESS_KEY   For updating IAM Policy
# IAMLIVE_USER_AWS_ACCESS_KEY_ID        For executing a command
# IAMLIVE_USER_AWS_SECRET_ACCESS_KEY    For executing a command
# IAMLIVE_IAM_POLICY_ARN                IAM Policy to update
### ---------------------------------------------------------------------------

### Usage ---------------------------------------------------------------------
# Build the Docker image
# docker build -t iamlive .
#
# ./automate.sh aws s3 ls
# ./automate.sh cd "${PWD}/terraform-dir/" ; terraform apply -auto-approve
### Usage ---------------------------------------------------------------------

set -e
set -o pipefail


_DOTENV_PATH="${IAMLIVE_DOTENV_PATH:-"${PWD}/.env"}"

if [[ -f "$_DOTENV_PATH" && $(wc .env -c | cut -d" " -f1) -gt 0  ]]; then
    # export $(cat .env | xargs)
    export $(grep -v '^#' .env | xargs)
fi

# Global Variables
_VERBOSE="${IAMLIVE_VERBOSE:-"true"}"
_DEBUG="${IAMLIVE_DEBUG:-"false"}"

# Credentials
_ADMIN_AWS_ACCESS_KEY_ID="${IAMLIVE_ADMIN_AWS_ACCESS_KEY_ID:-""}"
_ADMIN_AWS_SECRET_ACCESS_KEY="${IAMLIVE_ADMIN_AWS_SECRET_ACCESS_KEY:-""}"
_USER_AWS_ACCESS_KEY_ID="${IAMLIVE_USER_AWS_ACCESS_KEY_ID:-""}"
_USER_AWS_SECRET_ACCESS_KEY="${IAMLIVE_USER_AWS_SECRET_ACCESS_KEY:-""}"

# Proxy Settings
_CONTAINER_NAME="${IAMLIVE_CONTAINER_NAME:-"iamlive"}"
_HTTP_PROXY="${HTTP_PROXY:-"http://127.0.0.1:80"}"
_HTTPS_PROXY="${HTTPS_PROXY:-"http://127.0.0.1:443"}"
_AWS_CA_BUNDLE="${AWS_CA_BUNDLE:-"$HOME/.iamlive/ca.pem"}"

# App
if [[ "$_DEBUG" = "true" ]]; then
    _LOG_FILE_PATH="/tmp/iamlive.log"
    _CA_DIR_PATH="/root/.iamlive"
else
    _LOG_FILE_PATH="/app/iamlive.log"
    _CA_DIR_PATH="/home/appuser/.iamlive"
fi

_EXECUTE_COMMAND="${IAMLIVE_EXECUTE_COMMAND:-"$@"}"
_RETRY_INTERVAL="${IAMLIVE_RETRY_INTERVAL:-"10"}"
_MAX_ATTEMPTS="${IAMLIVE_MAX_ATTEMPTS:-"20"}"
_WAIT_FOR_CONTAINER="${IAMLIVE_WAIT_FOR_CONTAINER:-"5"}"
_IAM_POLICY_ARN="${IAMLIVE_IAM_POLICY_ARN:-""}"

# Get from env var or from IAM_POLICY_ARN
_AWS_ACCOUNT_ID="${IAMLIVE_AWS_ACCOUNT_ID:-"$(echo "$_IAM_POLICY_ARN" | cut -d":" -f5)"}"
_MASKED_AWS_ACCOUNT_ID="${_AWS_ACCOUNT_ID/%????????/********}"


# Helper Functions
sanitize_msg(){
    local msg="$1"
    local sanitized
    sanitized="${msg//$_AWS_ACCOUNT_ID/$_MASKED_AWS_ACCOUNT_ID}"
    echo "$sanitized"
}


msg_error(){
    local msg="$1"
    
    echo -e ">> [ERROR]: $(sanitize_msg "$msg")"
    cleanup_iamlive    
    exit 1
}


msg_log(){
    local msg="$1"
    if [[ $_VERBOSE = "true" ]]; then
        echo -e ">> [LOG]: $(sanitize_msg "$msg")"
    fi
}


# App Functions
copy_ca_from_container(){
    msg_log "Attempting to copy $_AWS_CA_BUNDLE from the container $_CONTAINER_NAME"
    docker cp "${_CONTAINER_NAME}:${_CA_DIR_PATH}/" "$HOME/"    
    msg_log "Successfully copied"
}


vars_validation(){

    if [[ -z "$_ADMIN_AWS_ACCESS_KEY_ID" || -z "$_ADMIN_AWS_SECRET_ACCESS_KEY" ]]; then
        msg_error "Missing AWS credentials for ADMIN"
    fi

    if [[ -z "$_USER_AWS_ACCESS_KEY_ID" || -z "$_USER_AWS_SECRET_ACCESS_KEY" ]]; then
        msg_error "Missing AWS credentials for USER"
    fi

    if [[ -z "$_EXECUTE_COMMAND" ]]; then
        msg_error "Missing command to execute"
    fi

    if [[ -z "$_IAM_POLICY_ARN" ]]; then
        msg_error "Missing IAM_POLICY_ARN"
    fi

    msg_log "Passed variables validation"
}


is_proxy_online(){
    local http_proxy_response
    local http_proxy_response
    http_proxy_response="$(curl -i "$_HTTP_PROXY" 2>&1 || true)"
    https_proxy_response="$(curl -i "$_HTTPS_PROXY" 2>&1 || true)"
    if [[ "$http_proxy_response" =~ "This is a proxy server" || "$https_proxy_response" =~ "This is a proxy server" ]] ; then
        msg_log "Passed Proxy Server check"
    else
        msg_error "Proxy server is not responding\nHTTP_PROXY_RESPONSE:\n$http_proxy_response\nHTTPS_PROXY_RESPONSE:\n$https_proxy_response"
    fi
}


set_proxy_env_vars(){
    export HTTP_PROXY="$_HTTP_PROXY"
    export HTTPS_PROXY="$_HTTPS_PROXY"
    export AWS_CA_BUNDLE="$_AWS_CA_BUNDLE"
}


unset_credentials(){
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
}


unset_proxy_env_vars(){
    unset HTTP_PROXY HTTPS_PROXY AWS_CA_BUNDLE 
}


get_oldest_iam_policy_versionid(){
    local policy_arn="$1"
    aws iam list-policy-versions --policy-arn "$policy_arn" --output=json | jq -cr '.Versions | sort_by(.CreateDate) | .[0].VersionId'
}


delete_iam_policy_versionid(){
    local policy_arn="$1"
    local policy_versionid="$2"
    aws iam delete-policy-version --policy-arn "$policy_arn" --version-id "$policy_versionid"
}


cleanup_iamlive(){
    if [[ "$(is_container_running)" = "true" && "$_DEBUG" != "true" ]]; then
        msg_log "Removing existing iamlive container"
        docker rm -f iamlive > /dev/null || true
        sleep 1
    fi
}

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT
ctrl_c() {
    msg_log "Terminating ..."
    cleanup_iamlive
    exit 0
}


is_container_running(){
  local container_exists
  container_exists="$(docker container inspect iamlive 2>&1 || true)"
  if [[ "$container_exists" =~ "No such container" ]]; then
    echo "false"
  else
    echo "true"
  fi
}


start_iamlive(){
    if [[ "$(is_container_running)" = "false" ]]; then
        msg_log "Starting iamlive container ..."
        docker run \
        -p 80:10080 \
        -p 443:10080 \
        --name iamlive \
        -d \
        -it iamlive \
        --mode proxy \
        --bind-addr 0.0.0.0:10080 \
        --force-wildcard-resource \
        --output-file "$_LOG_FILE_PATH"
        msg_log "Waiting $_WAIT_FOR_CONTAINER seconds for iamlive to be ready"
        sleep "$_WAIT_FOR_CONTAINER"
    fi

    is_proxy_online
    copy_ca_from_container
}


admin_add_policy(){
    local latest_iam_policy_document
    local oldest_policy_versionid
    local delete_oldest_versionid_results
    local create_policy_results_initial
    local create_policy_results_final
    latest_iam_policy_document="$1"
    export AWS_ACCESS_KEY_ID="$_ADMIN_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$_ADMIN_AWS_SECRET_ACCESS_KEY"
    msg_log "Creating IAM policy version to $_IAM_POLICY_ARN"
    unset_proxy_env_vars
    create_policy_results_initial="$(aws iam create-policy-version \
        --policy-arn "$_IAM_POLICY_ARN" \
        --policy-document "$latest_iam_policy_document" \
        --set-as-default 2>&1 || true)"

    if [[ "$create_policy_results_initial" =~ (LimitExceeded) ]]; then
        msg_log "Attempt to delete oldest policy version"
        oldest_policy_versionid="$(get_oldest_iam_policy_versionid "$_IAM_POLICY_ARN")"
        if [[ "$oldest_policy_versionid" =~ v[0-9]+ ]]; then
            msg_log "Deleting policy version id: $oldest_policy_versionid"
        else
            msg_error "Invalid version id $oldest_policy_versionid, must be: v1, v2, ..., v5"
        fi

        delete_oldest_versionid_results="$(delete_iam_policy_versionid "$_IAM_POLICY_ARN" "$oldest_policy_versionid" 2>&1 || true)"
        if [[ -z "$delete_oldest_versionid_results" ]]; then
            msg_log "Successfully deleted the policy version id $oldest_policy_versionid"
        else
            msg_error "Failed to delete the policy version id $oldest_policy_versionid"
        fi

        msg_log "Attempt to create the latest policy version"
        create_policy_results_final="$(aws iam create-policy-version \
            --policy-arn "$_IAM_POLICY_ARN" \
            --policy-document "$latest_iam_policy_document" \
            --set-as-default 2>&1 || true)"
        echo "$create_policy_results_final"
    else
        echo "$create_policy_results_initial"        
    fi
}


execute_command(){
    local my_command
    local results
    my_command="$*"
    results=$(eval $my_command 2>&1 || true)
    echo "$results"
}


decode_aws_error_msg(){
    local encoded_msg="$1"
    export AWS_ACCESS_KEY_ID="$2"
    export AWS_SECRET_ACCESS_KEY="$3"  
    unset_proxy_env_vars
    if [[ -z "$encoded_msg" ]]; then
        msg_error "Encoded message is empty."
    fi
    aws sts decode-authorization-message \
        --encoded-message "$encoded_msg" | jq
}


user_invoke_command(){
    local command_results
    local iamlive_policy_document
    local decoded_error_msg
    declare -a decoded_error_msgs
    local diff_output
    local latest_iam_policy_document

    export AWS_ACCESS_KEY_ID="$_USER_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$_USER_AWS_SECRET_ACCESS_KEY"
    msg_log "Executing: $_EXECUTE_COMMAND"
    set_proxy_env_vars
    command_results="$(execute_command $_EXECUTE_COMMAND 2>&1 || true)"
    echo "$command_results"

    if [[ "$_DEBUG" != "true" ]]; then
        docker exec "$_CONTAINER_NAME" kill -HUP 1
        sleep 2
        iamlive_policy_document="$(docker exec "$_CONTAINER_NAME" cat $_LOG_FILE_PATH)"
    fi

    # Handle AWS CLI
    if [[ "$command_results" =~ (.*AccessDenied.*|fatal.*error.*403) ]]; then
        unset_credentials
        unset_proxy_env_vars
        msg_log "Getting policy from $_CONTAINER_NAME:$_LOG_FILE_PATH"
        docker exec "$_CONTAINER_NAME" kill -HUP 1
        latest_iam_policy_document="$(docker exec "$_CONTAINER_NAME" cat $_LOG_FILE_PATH)"
        echo "$latest_iam_policy_document"
        if [[ -z $(echo "$latest_iam_policy_document" | jq -rc '.Statement[]') ]]; then
            msg_error "Empty policy document"
        fi
        admin_add_policy "$latest_iam_policy_document"
        msg_log "Differences between current and latest policies:"
        diff <(echo "$iamlive_policy_document") <(echo "$latest_iam_policy_document") || true
    elif [[ "$command_results" =~ .*status.*code.*403 ]]; then
    # Handle Terraform CLI
        unset_credentials
        unset_proxy_env_vars
        msg_log "Getting policy from $_CONTAINER_NAME:$_LOG_FILE_PATH"
        docker exec "$_CONTAINER_NAME" kill -HUP 1
        sleep 1
        latest_iam_policy_document="$(docker exec "$_CONTAINER_NAME" cat $_LOG_FILE_PATH)"        
        echo "$latest_iam_policy_document"
        if [[ -z $(echo "$latest_iam_policy_document" | jq -rc '.Statement[]') ]]; then
            msg_error "Empty policy document"
        fi
        admin_add_policy "$latest_iam_policy_document"

        diff_output="$(diff <(echo "$iamlive_policy_document") <(echo "$latest_iam_policy_document") || true)"
        if [[ -n "$diff_output" ]]; then
            msg_log "Differences between current and latest policies:"        
            echo "$diff_output"
        elif [[ -z "$diff_output" && "$command_results" =~ "Encoded authorization failure message" ]]; then
            msg_log "No differences between current and latest policies"
            msg_log "Attempting to decode encoded messages ..."
            readarray -t encoded_error_msgs <<<"$command_results"
            for encoded_error_msg in "${encoded_error_msgs[@]}"; do
                encoded_error_msg="${encoded_error_msg##* }" # Clean prefix
                if [[ "${#encoded_error_msg}" -ge 512 ]]; then
                    decoded_error_msg="$(decode_aws_error_msg "$encoded_error_msg" "$_ADMIN_AWS_ACCESS_KEY_ID" "$_ADMIN_AWS_SECRET_ACCESS_KEY")"
                    if [[ ! " ${decoded_error_msgs[*]} " =~ " ${decoded_error_msg} " ]]; then
                        decoded_error_msgs+=("$decoded_error_msg")
                    fi
                fi
            done
            msg_log "Missing permissions:\n$(echo "${decoded_error_msgs[@]}" | jq '.DecodedMessage | fromjson | {action: .context.action, resource: .context.resource}')"
            msg_error "TODO: Handle missing permissions"
        fi
    else
        msg_log "Unknown output - check the logs"
        exit 0
    fi

    unset_credentials
    unset_proxy_env_vars
}


main(){
    vars_validation
    cleanup_iamlive

    local i
    i=0
    while [[ $i -lt "$_MAX_ATTEMPTS" ]]; do
        start_iamlive
        user_invoke_command
        msg_log "Sleeping $_RETRY_INTERVAL seconds, before the next exection ..."
        sleep "$_RETRY_INTERVAL"
        i=$((i+1))
    done

    msg_error "Excceeded max attempts - $_MAX_ATTEMPTS"
}


# Main
main