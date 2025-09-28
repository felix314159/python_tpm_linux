# Prerequisites (Ubuntu/Debian):
#   sudo apt install tpm2-tools
#   sudo usermod -aG tss $USER   # reboot so /dev/tpmrm0 perms apply
# Ensure this now works without sudo:
#   tpm2_getrandom 8

# --------------------------------------------------------------------

# List available NV indices:
#   tpm2_getcap handles-nv-index


# Get max size of any value you may write:
#   tpm2_getcap properties-fixed | grep -A1 TPM2_PT_NV_INDEX_MAX
#   -> on my tpm that is: 0x800 = 2048 chars

# Ensure what the largest chunk is you can write in one go:
#   tpm2_getcap properties-fixed | grep -A1 TPM2_PT_NV_BUFFER_MAX
#   -> on my tpm that matches the max value size 0x800, so don't have to worry about the buffer

# Determining the total amount of available storage is not that straightforward it seems
# The only guarantee you have from specs is at least 6962 bytes

# --------------------------------------------------------------------

# READ METADATA OF NV INDEX EXAMPLE:
#   tpm2_nvreadpublic 0x1410001

# READ ACTUAL VALUE (if no password required):
#   tpm2_nvread -C 0x01800000 -s 11 0x01800000

# READ ACTUAL VALUE (password 123 required):
#   tpm2_nvread -C 0x01800000 -s 11 0x01800000  -P 123


# DELETE KEY:VALUE PAIR (if no password required):
#   tpm2_nvundefine -C o 0x01800001

# DELETE KEY:VALUE PAIR (if password required):
#   tpm2_nvundefine -C o 0x01800001 -P 123

# WRITE EXAMPLE 1 (NO PASSWORD PROTECTION):
# User values are safe to be written in range [0x01800000, 0x01BFFFFF]
# Commands to write "hello world" (length: 11 chars) to 0x01800000:
#   1. Create a key that is able to store a string of length 11
#       tpm2_nvdefine -C o -s 11 -a "authread|authwrite|no_da|orderly" 0x01800000
#       -> Response: nv-index: 0x1800000
#   2. Assign value to that key:
#       printf "hello world" | tpm2_nvwrite -C 0x01800000 -i - 0x01800000
# Now you can see that key-value pair via: `tpm2_nvreadpublic 0x01800000`
# And get the string in human-readable form via: `tpm2_nvread -C 0x01800000 -s 11 0x01800000`

# WRITE EXAMPLE 2 (WITH PASSWORD PROTECTION):
# Goal: Write "hello world" to 0x01800001 and you need password "123" to access it:
#   tpm2_nvdefine -C o -s 11 -a "authread|authwrite|no_da|orderly" -p 123 0x01800001
#   printf "hello world" | tpm2_nvwrite -C 0x01800001 -P 123 -i - 0x01800001
# Try to read without pw (will fail: `authorization failure without DA implications`):
#   tpm2_nvread -C 0x01800001 -s 11 0x01800001
# Read with pw (great success):
#   tpm2_nvread -C 0x01800001 -s 11 0x01800001 -P 123

# ---------------------------------------------------------------------

import subprocess
import yaml
from typing import Dict, List, Any
from pprint import pprint

# ------ Helper class to always print stuff in its hex representation if possible ------

class HexInt(int):
    def __repr__(self):
        return hex(self)


def hexify(obj):
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return HexInt(obj)
    if isinstance(obj, dict):
        return {hexify(k): hexify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [hexify(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(hexify(x) for x in obj)
    if isinstance(obj, set):
        return {hexify(x) for x in obj}
    return obj

# -------------------------- Run commands -------------------------------

def run_command(*, command: List[str], input: str = None) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            input=input
        )
    except Exception as e:
        err_msg = (
            f"Command failed: {command}\n"
            f"exit:{e.returncode}\n"
            f"stdout:\n{e.stdout}\n"
            f"stderr:\n{e.stderr}"
        )
        exit(err_msg)

    return result


def run_command_yaml(command: List[str]) -> Any:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8"
        )
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, (bytes, bytearray)) else (e.stderr or "")
        raise RuntimeError(f"Command failed: {command}\n{err}") from e
    if result.stderr:
        raise RuntimeError(f"Command wrote to stderr: {command}\n{result.stderr}")

    out = result.stdout.strip()
    if not out:
        return None

    docs = list(yaml.safe_load_all(out))
    # use hex representation of int
    docs = hexify(docs)
    return docs[0] if len(docs) == 1 else docs

# ----------------------------------------- TPM functions ----------------------------------------

def tpm_sanity_check() -> None:
    """Ensures that tmp2-tools is installed correctly and we can read/write without root."""
    result: subprocess.CompletedProcess = run_command(command=["tpm2_getrandom", "8"])
    assert len(result.stdout) == 8, f"Failed to run 'tpm2_getrandom 8', please read the comments of this file."


def tpm_get_nv_indices() -> List[int]:
    result: subprocess.CompletedProcess = run_command_yaml(["tpm2_getcap", "handles-nv-index"])
    return result


def tpm_get_nv_index_metadata(*, index: int) -> Dict[Any,Any]:
    # ensure that nv-index exists
    nv_indices_list: List[int] = tpm_get_nv_indices()
    assert index in nv_indices_list, f"You tried to get metadata of nv-index 0x{index:x} but it does not exist"

    result: subprocess.CompletedProcess = run_command_yaml(["tpm2_nvreadpublic", str(index)])

    return result


def tpm_read_nvm(*, index: int, pwd: str = None) -> str:
    # get length of value we want to read
    nv_index = tpm_get_nv_index_metadata(index=index)
    nvm_length = nv_index.get(index).get("size")

    index_str = str(index)
    command = ["tpm2_nvread", "-C", index_str, "-s", str(nvm_length), index_str]
    if pwd:
        command.extend(["-P", pwd])
    
    try:
        result: subprocess.CompletedProcess = run_command(command=command)
        result_str = result.stdout.decode() # b"" to ""
        return result_str
    except Exception as e:
        print(f"Failed to read value. Have you not provided the correct required password?")
        return e


def tmp_get_hardware_info() -> Dict[str, Any]:
    result: subprocess.CompletedProcess = run_command_yaml(["tpm2_getcap", "properties-fixed"])
    return result


def tpm_write(*, key: int, value: str, pwd: str = None) -> None:
    # sanity check 1: key is in user-memory interval (this is not specced AFAIK, more like an agreement that vendors avoid this range)
    assert 0x01800000 <= key <= 0x01BFFFFF, f"You tried to write to key {key} but that is not within [0x01800000,0x01BFFFFF]"

    # sanity check 2: value length is within certain bounds
    #   ensure that value fits as one chunk (we never try splitting)
    value_len = len(value)
    #       get hw info
    hw_info = tmp_get_hardware_info()
    #       get max allowed chunk size
    chunk_max_size: HexInt = hw_info.get("TPM2_PT_NV_BUFFER_MAX").get("raw")
    assert value_len <= chunk_max_size, f"Your TPM allows max buffer size {chunk_max_size} but you tried to write a string of length {value_len} in one go"
    #       probably not necessary cuz i would like to think that TPM2_PT_NV_BUFFER_MAX<=TPM2_PT_NV_INDEX_MAX, but let's ensure that we can really write the string
    max_value_len = hw_info.get("TPM2_PT_NV_INDEX_MAX").get("raw")
    assert value_len <= max_value_len, f"Your TPM allows max value length {max_value_len} but you tried to write a string of length {value_len}"
    #   Note: Writing may still fail if there is no free storage left, but there is no straightforward way to determine total free user-writable storage

    # sanity check 3: do NOT overwrite existing values, so check if that key is already used or not
    nv_indices_list: List[int] = tpm_get_nv_indices()
    assert key not in nv_indices_list, f"You tried to write to key 0x{key:x} but that key already is populated"

    # sanity check 4: if pwd was provided, ensure it is not omegalulweak
    if pwd:
        min_pwd_length = 5
        assert len(pwd) >= min_pwd_length, f"Provided password is too short: {pwd}. It has {len(pwd)} chars but min length requirement is {min_pwd_length}"

    # ------------------------------------------------------------------------------------------

    # create nv index
    #       get target key as hex_str
    key_str = str(f"0x{key:x}")
    
    if pwd:
        command = ["tpm2_nvdefine", "-C", "o", "-s", str(value_len), "-a", "authread|authwrite|no_da|orderly", "-p", pwd, key_str]
    else:
        command = ["tpm2_nvdefine", "-C", "o", "-s", str(value_len), "-a", "authread|authwrite|no_da|orderly", key_str]
    
    #       if this fails, you probably have no storage left, delete a few key:value pairs you know (careful tho lol)
    result: subprocess.CompletedProcess = run_command_yaml(command=command)
    result_response = result.get("nv-index")
    assert result_response == key, f"Failed to create nv-index, expect response {key} but got {result_response}"
    
    # write value
    if pwd:
        command = ["tpm2_nvwrite", "-C", key_str, "-P", pwd, "-i", "-", key_str]
    else:
        command = ["tpm2_nvwrite", "-C", key_str, "-i", "-", key_str]
    run_command(command=command, input=value.encode("utf-8"))

    # -----------------------------------------------------------------------------------------

    # write was only successful if reading works
    assert tpm_read_nvm(index=key, pwd=pwd) == value

    print("Successfully wrote key value pair.")


def tpm_delete_index(*, key: int) -> None:
    # ensure what you try to delete exists
    nv_indices_list: List[int] = tpm_get_nv_indices()
    assert key in nv_indices_list, f"You tried to delete key 0x{key:x} but that key does not exist"

    key_str = str(f"0x{key:x}")
    command = ["tpm2_nvundefine", "-C", "o", key_str]

    run_command(command=command)
    print(f"Successfully deleted nv-index 0x{key:x}")


def main():
    # ensure everything is installed and set-up correctly
    tpm_sanity_check()

    # get list of existing nv (non-volatile) indices
    nv_indices_list: List[int] = tpm_get_nv_indices()
    pprint(nv_indices_list)

    # get index metadata
    # target_index = 0x01800013
    # nv_index: Dict[Any, Any]= tpm_get_nv_index_metadata(index=target_index)
    # pprint(nv_index)

    # read nvm
    #value = tpm_read_nvm(index=0x01800013)
    #print(f"Read Value: {value}") # could be invisible chars when printed
    #value2 = tpm_read_nvm(index=0x01800013, pwd="abcde")
    #print(value2)

    # # write key:value pair to nv memory (not password protected)
    #tpm_write(key=0x01800013, value="abcyo")

    # write key:value pair to nv memory (password protected)
    #tpm_write(key=0x01800013, value="abcyoo", pwd="abcde")

    #tpm_delete_index(key=0x01800013)

main()
# i still have to look into owner-pw vs index-pw (and -P and -p difference)
# maybe there is a simple way so that you can't just delete without knowing the pw
# im using -C o (owner hierarchy) but there also is -C p (platform hierarchy)
