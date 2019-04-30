#!/usr/local/Cellar/bash/5.0.7/bin/bash

set -euo pipefail

declare -A secrets=( )
declare vaultFile="${VAULT_SH_VAULT-}"
declare keyFile="${VAULT_SH_KEYFILE-}"

# Load vault from file
function loadVault() {
  if [[ -z "$vaultFile" ]]; then
      echo "missing variable: VAULT_SH_VAULT"
      exit 1
  fi
  if [[ -z "$keyFile" ]]; then
      echo "missing variable: VAULT_SH_KEYFILE"
      exit 1
  fi
  if [ -f $vaultFile ]; then
    if [ -f $keyFile ]; then
      while IFS='=' read -r key value; do
        if [[ ! -z "$key" ]]; then
          secrets[$key]=$value
        fi
      done <<< $(cat $vaultFile | openssl enc -aes-256-cbc -d -pass file:$keyFile)
    else
      echo "keyfile $keyFile not found"
      exit 1
    fi
  else
    echo "vault $vaultFile not found"
    exit 1
  fi
}

# Save vault to file
function saveVault() {
  if [[ -z "$vaultFile" ]]; then
      echo "missing variable: VAULT_SH_VAULT"
      exit 1
  fi
  if [[ -z "$keyFile" ]]; then
      echo "missing variable: VAULT_SH_KEYFILE"
      exit 1
  fi
  if [ -f $keyFile ]; then
    local output=""
    for key in "${!secrets[@]}"
    do
      output+="${output}$key=${secrets[$key]}\n"
    done
    printf "%b" "$output" | openssl enc -aes-256-cbc -pass file:$keyFile > $vaultFile
  else
    echo "keyfile $keyFile not found"
    exit 1
  fi
}

function setSecret() {
  local key=${1-}
  local secret=${2-}

  echo "Stored ${key} in $VAULT_SH_VAULT"
  secrets[$key]=$secret
}

function getSecret() {
  local key=${1-}

  if [[ -z "$key" ]]; then
      echo "Usage: get <key>"
      exit 1
  fi

  if ! [[ ${secrets[$key]+abc} ]]; then
      echo "$key not found in vault"
      exit 1
  fi

  local value="${secrets[$key]}"
  if [[ -z "$value" ]]; then
      echo "$key not found in vault"
      exit 1
  fi
  echo "$value"
}

function showHelp() {
  echo "Vault.sh"
  echo ""
  echo "Vault.sh is a simple bash script for creating an encrypted key-value database using OpenSSL with a keyfile"
  echo ""
  echo "Commands:"
  echo "  help           Show this information that you're already reading..."
  echo "  init           Initialize a new Vault and generate a Keyfile for it"
  echo "  list           List all keys from the vault"
  echo "  set <value>    Store a new secret into the vault"
  echo "  get <key>      Get a secret from the vault"
}

function genKey {
  if [[ -z "$keyFile" ]]; then
      echo "missing variable: VAULT_SH_KEYFILE"
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

case "${1-help}" in
  init)
      if [[ -z "$vaultFile" ]]; then
          echo "missing variable: VAULT_SH_VAULT"
          exit 1
      fi
      if [ -f $vaultFile ]; then
        echo "Vault '$vaultFile' already exists"
        exit 1
      fi
      genKey
      saveVault
      echo "Created vault '$vaultFile', with keyfile '$keyFile'"
      ;;
  set)
      secret=''
      read -s -p "Secret: " secret
      echo
      if [[ -z "$secret" ]]; then
          echo "Cannot store empty secret"
          exit 1
      fi
      loadVault
      setSecret ${2-} ${secret-}
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