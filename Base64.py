BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BASE64_PAD = "="



def encode_base64(input_string):
    input_bytes = input_string.encode("utf-8")
    
    encoded_string = ""
    
    for i in range(0, len(input_bytes), 3):
        chunk = input_bytes[i:i+3]
        
        bit_string = "".join(f"{byte:08b}" for byte in chunk)
        
        base64_groups = [bit_string[j:j+6] for j in range(0, len(bit_string), 6)]
        
        while len(base64_groups[-1]) < 6:
            base64_groups[-1] += "0"
        
        base64_indexes = [int(group, 2) for group in base64_groups]
        
        encoded_string += "".join(BASE64_ALPHABET[index] for index in base64_indexes)
        
        if len(chunk) < 3:
            encoded_string = encoded_string[:-1] + BASE64_PAD * (3 - len(chunk))
    
    return encoded_string

def decode_base64(encoded_string):
    encoded_string = encoded_string.rstrip(BASE64_PAD)
    
    decoded_bytes = bytearray()
    
    for i in range(0, len(encoded_string), 4):
        chunk = encoded_string[i:i+4]
        
        bit_string = "".join(f"{BASE64_ALPHABET.index(char):06b}" for char in chunk)
        
        byte_groups = [bit_string[j:j+8] for j in range(0, len(bit_string), 8)]
        
        decoded_bytes.extend(int(group, 2) for group in byte_groups)
    
    return bytes(decoded_bytes)

if __name__ == "__main__":
    original_string = "Hello, world!"
    print("Original:", original_string)

    encoded = encode_base64(original_string)
    print("Encoded:", encoded)

    decoded = decode_base64(encoded)
    print("Decoded:", decoded.decode("utf-8"))
