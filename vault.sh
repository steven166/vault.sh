#!/bin/bash

set -euo pipefail

declare -A secrets=( )
declare vaultFile="${VAULT_SH_VAULT-}"
declare keyFile="${VAULT_SH_KEYFILE-}"
declare VAULT_VERSION=1
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

      decryptPipe="openssl enc -aes-256-cbc -md md5 -d -pass file:$keyFile"
      if [ "$VAULT_ENCRYPT" == "false" ]; then
        decryptPipe="cat"
      fi

      while IFS=':' read -r key value; do
        if [ "$key" == "#vault.sh" ] && [ "$line_number" -eq "0" ]; then
          VAULT_VERSION=$value
        else
          if [[ ! -z "$key" ]]; then
            if [ ${secrets[$key]+abc} ]; then
              unset secrets["$key"]
            fi
            case "$VAULT_VERSION" in
                1)
                    key_part=$(echo $key | cut -d '=' -f 1)
                    value_part=$(echo $key | cut -d '=' -f 2-)
                    secrets[$key_part]=$value_part 
                    ;;
                2)
                    secrets[$key]=$value
                    ;;
                *)
                    echo "Unknown vault version: $VAULT_VERSION"
                    exit 1
                    ;;
            esac
          fi
        fi
        line_number=$(($line_number + 1))
      done <<< $(cat $vaultFile | $decryptPipe)
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

  encryptPipe="openssl enc -aes-256-cbc -md md5 -pass file:$keyFile"
  if [ "$VAULT_ENCRYPT" == "false" ]; then
    encryptPipe="cat"
  fi

  if [ -f $keyFile ]; then
    local output=""
    output="#vault.sh:2\n"
    for key in "${!secrets[@]}"
    do
      case "$VAULT_VERSION" in
          1)
              output="${output}$key:$(b64enc ${secrets[$key]})\n"
              ;;
          2)
              output="${output}$key:${secrets[$key]}\n"
              ;;
      esac
    done
    printf "%b" "$output" | sort | $encryptPipe > $vaultFile
  else
    >&2 echo "keyfile $keyFile not found"
    exit 1
  fi
}

function setSecret() {
  local key=${1-}
  local secret="${2-}"

  echo "Stored ${key} in $VAULT_SH_VAULT"
  if [ ${secrets[$key]+abc} ]; then
    unset secrets["$key"]
  fi
  secrets[$key]="$secret"
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
  printf "%s" "$(b64dec $value)"
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
  echo $1 | base64
}

function b64dec {
  (echo $1 | base64 -D 2> /dev/null) || (echo $1 | base64 -d)
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
        secret=$(echo $input | openssl base64 -A)
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


# saveVault "vault" "key"
# loadVault "vault" "key"
# insertSecret "my-password" "blabla"
# insertSecret "my-password2" "bla2bla"
# saveVault "vault" "key"
# echo ${secrets["my-password"]}
# echo ${secrets["my-password2"]}
