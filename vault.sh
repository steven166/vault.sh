#!/bin/bash

set -euo pipefail

declare -A secrets=( )
declare vaultFile="${VAULT_SH_VAULT-}"
declare keyFile="${VAULT_SH_KEYFILE-}"
declare VAULT_VERSION=1
declare CURRENT_VAULT_VERSION=3
declare VAULT_ENCRYPT=true

# Load vault from file
function loadVault() {
  if [[ -z "$vaultFile" ]]; then
      >&2 echo "missing variable: VAULT_SH_VAULT"
      exit 1
  fi
  if [[ -z "$keyFile" ]]; then
      >&2 echo "missing variable: VAULT_SH_KEYFILE"
      exit 1
  fi
  if [ -f $vaultFile ]; then
    if [ -f $keyFile ]; then
      line_number=0

      vault_version="1"
      vault_version_info=$(head -n 1 $vaultFile)
      if [[ $vault_version_info == "#vault.sh:"* ]]; then
        vault_version=$(echo $vault_version_info | cut -d: -f2)
      fi

      decryptPipe="decrypt $keyFile"
      if [ "$VAULT_ENCRYPT" == "false" ]; then
        decryptPipe="cat"
      fi

      if [ "$vault_version" == "1" ]; then
        # Lagacy
        while IFS=':' read -r key value; do
          if [ "$key" == "#vault.sh" ] && [ "$line_number" -eq "0" ]; then
            vault_version=$value
          else
            if [[ ! -z "$key" ]]; then
              if [ ${secrets[$key]+abc} ]; then
                unset secrets["$key"]
              fi
              if [[ ! -z "$value" ]]; then
                case "$vault_version" in
                    1)
                        key_part=$(echo $key | cut -d '=' -f 1)
                        value_part=$(echo $key | cut -d '=' -f 2-)
                        secrets[$key_part]=$(printf $value_part | b64dec | encrypt $keyFile | b64enc)
                        ;;
                    2)
                        secrets[$key]=$(printf $value | b64dec | encrypt $keyFile | b64enc)
                        ;;
                    *)
                        echo "Unknown vault version: $vault_version"
                        exit 1
                        ;;
                esac
              fi
            fi
          fi
          line_number=$(($line_number + 1))
        done <<< $(cat $vaultFile | openssl enc -aes-256-cbc -md md5 -d -pass file:$keyFile)
      else
        while IFS=":" read -r key value; do
            if [[ ! -z "$key" ]]; then
              if [[ "$key" != "#"* ]]; then
                if [ ${secrets[$key]+abc} ]; then
                  unset secrets["$key"]
                fi
                case "$vault_version" in
                    3)
                        if [ "$VAULT_ENCRYPT" == "false" ]; then
                          secrets[$key]=$(printf $value | b64dec | encrypt $keyFile | b64enc)
                        else
                          secrets[$key]=$value
                        fi
                        ;;
                    *)
                        echo "Unknown vault version: $vault_version"
                        exit 1
                        ;;
                esac
              fi
            fi
        done <<< $(cat $vaultFile)
      fi
    else
      >&2 echo "keyfile $keyFile not found"
      exit 1
    fi
  else
    >&2 echo "vault $vaultFile not found"
    exit 1
  fi
}

# Save vault to file
function saveVault() {
  if [[ -z "$vaultFile" ]]; then
      >&2 echo "missing variable: VAULT_SH_VAULT"
      exit 1
  fi
  if [[ -z "$keyFile" ]]; then
      >&2 echo "missing variable: VAULT_SH_KEYFILE"
      exit 1
  fi

  if [ -f $keyFile ]; then
    local output=""
    output="#vault.sh:${CURRENT_VAULT_VERSION}\n"
    for key in "${!secrets[@]}"
    do
      if [ "$VAULT_ENCRYPT" == "false" ]; then
        output="${output}$key:$(printf ${secrets[$key]} | b64dec | decrypt $keyFile | b64enc)\n"
      else
        output="${output}$key:${secrets[$key]}\n"
      fi
    done
    printf "%b" "$output" | sort > $vaultFile
  else
    >&2 echo "keyfile $keyFile not found"
    exit 1
  fi
}

function setSecret() {
  local key=${1-}
  local secret="${2-}"

  if [[ -z "$keyFile" ]]; then
      >&2 echo "missing variable: VAULT_SH_KEYFILE"
      exit 1
  fi

  echo "Stored ${key} in $VAULT_SH_VAULT"
  if [ ${secrets[$key]+abc} ]; then
    unset secrets["$key"]
  fi
  secrets[$key]="$(printf $secret | b64dec | encrypt $keyFile | b64enc)"
}

function removeSecret() {
  local key=${1-}

  if ! [[ ${secrets[$key]+abc} ]]; then
      >&2 echo "$key not found in vault"
      exit 1
  fi
  unset secrets["$key"]
}

function getSecret() {
  local key=${1-}

  if [[ -z "$keyFile" ]]; then
      >&2 echo "missing variable: VAULT_SH_KEYFILE"
      exit 1
  fi

  if [[ -z "$key" ]]; then
      >&2 echo "Usage: get <key>"
      exit 1
  fi

  if ! [[ ${secrets[$key]+abc} ]]; then
      >&2 echo "$key not found in vault"
      exit 1
  fi

  local value="${secrets[$key]}"
  if [[ -z "$value" ]]; then
      >&2 echo "$key not found in vault"
      exit 1
  fi
  printf "%s" "$(printf $value | b64dec | decrypt $keyFile)"
}

function showHelp() {
  echo "Vault.sh"
  echo ""
  echo "Vault.sh is a simple bash script for creating an encrypted key-value database using OpenSSL with a keyfile"
  echo ""
  echo "Commands:"
  echo "  help                     Show this information that you're already reading..."
  echo "  init                     Initialize a new Vault and generate a Keyfile for it"
  echo "  list                     List all keys from the vault"
  echo "  set <value>              Store a new secret into the vault"
  echo "  get <key>                Get a secret from the vault"
  echo "  rm <key>                 Remove a secret from the vault"
  echo "  export <file>            Export vault to plain file"
  echo "  import <file>            Import vault from plain file"
}

function genKey {
  if [[ -z "$keyFile" ]]; then
      >&2 echo "missing variable: VAULT_SH_KEYFILE"
      exit 1
  fi
  if [ -f $keyFile ]; then
    echo "Keyfile $keyFile already exists"
  else
    echo "Generate keyfile $keyFile"
    openssl rand 256 > $keyFile
  fi
}

function list {
  echo "Stored Keys:"
  for key in "${!secrets[@]}"
  do
    echo "- $key"
  done
}

function export {
  exportFile=${1-}
  if [[ -z "$exportFile" ]]; then
      >&2 echo "Usage: export <exportFile>"
      exit 1
  fi
  loadVault
  VAULT_ENCRYPT=false
  vaultFile=$exportFile
  saveVault
}

function import {
  importFile=${1-}
  if [[ -z "$importFile" ]]; then
      >&2 echo "Usage: import <importFile>"
      exit 1
  fi

  targetVaultFile=$vaultFile
  vaultFile=$importFile
  VAULT_ENCRYPT=false
  loadVault
  VAULT_ENCRYPT=true
  vaultFile=$targetVaultFile
  saveVault
}

function b64enc {
  read input
  printf $input | base64
}

function b64dec {
  read input
  (printf $input | base64 -D 2> /dev/null) || (printf $input | base64 -d)
}

function decrypt {
  read input
  printf $input | openssl enc -aes-256-cbc -md md5 -d -pass file:${1:-}
}

function encrypt {
  read input
  printf $input | openssl enc -aes-256-cbc -md md5 -pass file:${1:-}
}

case "${1-help}" in
  init)
      if [[ -z "$vaultFile" ]]; then
          >&2 echo "missing variable: VAULT_SH_VAULT"
          exit 1
      fi
      if [ -f $vaultFile ]; then
        >&2 echo "Vault '$vaultFile' already exists"
        exit 1
      fi
      genKey
      saveVault
      echo "Created vault '$vaultFile', with keyfile '$keyFile'"
      ;;
  set)
      secret=''
      if [ -p /dev/stdin ]; then
        secret=$(cat | openssl base64 -A)
      else
        read -s -p "Secret: " input
        echo
        if [[ -z "$input" ]]; then
          >&2 echo "Cannot store empty secret"
          exit 1
        fi
        secret=$(printf $input | openssl base64 -A)
      fi

      loadVault
      setSecret ${2-} "${secret-}"
      saveVault
      ;;
  rm)
      loadVault
      removeSecret ${2-}
      saveVault
      ;;
  get)
      loadVault
      getSecret ${2-}
      ;;
  list)
      loadVault
      list
      ;;
  export)
      export ${2-}
      ;;
  import)
      import ${2-}
      ;;
  help|\?|*)
      showHelp
      exit 1
      ;;
esac
