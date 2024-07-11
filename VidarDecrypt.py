import base64                                                   # used for base64 decoding
import re                                                       # used for cleaning up decrypted output
from ghidra.program.model.symbol import RefType                 # used for dealing with reference types
from ghidra.program.model.symbol import SourceType              # used for setting new variable name
from Crypto.Cipher import ARC4                                  # used for decrypting RC4

rc4_key = b"2910114286690104117195131148" ####### SET YOUR RC4 KEY HERE #######

# RC4 decryption 
def rc4_decrypt(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

# replace invalid characters with underscores or remove them
def sanitize_symbol_name(name):
    sanitized_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    return sanitized_name

function_list = getCurrentProgram().getFunctionManager().getFunctions(True) # get a handle to the fucntions
target_function = None

for function in function_list:
        if function.getName() == "FUN_0040254e": ####### SET THE TARGET FUNCTION NAME HERE (this must be the function where the encrypted strings are being passed to the decryption function itself) #######
                target_function = function
                break

function_body = target_function.getBody() # get handle to the target function
listing = getCurrentProgram().getListing() # get handle to all the instructions inside of program

symbol_table = getCurrentProgram().getSymbolTable() # get handle to symbol table

last_decrypted_string = None

for address in function_body.getAddresses(True): # iterate through every address in target function
        instruction = listing.getInstructionAt(address) # get the instruction at each address

        if instruction is not None:
            mnemonic = instruction.getMnemonicString() # get mnemonic 

            if mnemonic == "MOV":
                op0 = instruction.getDefaultOperandRepresentation(1)
                if op0 != "EAX":
                      ref = instruction.getPrimaryReference(1) # within the fetched instruction, get the second operand
                      if ref and ref.getReferenceType() == RefType.DATA:
                            string_data = listing.getDataAt(ref.getToAddress())
                            string_value = string_data.getValue()
                            if string_value != rc4_key.decode("utf-8"): # skip the rc4 key
                                decoded_bytes = base64.b64decode(string_value) # decode from base64
                                decrypted_bytes = rc4_decrypt(rc4_key, decoded_bytes) # decrypt using RC4
                                decrypted_string = decrypted_bytes.decode("utf-8")
                                sanitized_name = sanitize_symbol_name(decrypted_string) # remove invalid characters from the decrypted string
                                
                                last_decrypted_string = sanitized_name

            if mnemonic == "MOV" and instruction.getDefaultOperandRepresentation(1) == "EAX":
                if last_decrypted_string is not None:
                    ad0 = instruction.getAddress(0)
                    smb0 = symbol_table.getPrimarySymbol(ad0)
                    if smb0:
                         smb0.setName(last_decrypted_string, SourceType.USER_DEFINED) # rename the variable

