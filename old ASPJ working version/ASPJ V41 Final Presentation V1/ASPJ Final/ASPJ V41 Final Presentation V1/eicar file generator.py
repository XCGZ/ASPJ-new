eicar_content = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
jpg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\x09\x09\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f'
jpg_footer = b'\xff\xd9'
    
# Create the EICAR test file
with open('eicar_test_file.jpg', 'wb') as f:
    f.write(jpg_header)
    f.write(eicar_content.encode('utf-8'))  # Encode the string to bytes
    f.write(jpg_footer)