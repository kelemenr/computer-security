import doctest


def bin2hex(binary):
    """ 
    Converts a binary string to a hexadecimal string. 

    Examples:
        >>> bin2hex('1111')
        'f'
        >>> bin2hex('1')
        '1'
    """
    return hex(int(binary, 2))[2:]


def fillupbyte(binary):
    """ 
    Pads a binary string to the nearest byte. 

    Examples:
        >>> fillupbyte('011')
        '00000011'
        >>> fillupbyte('1')
        '00000001'
        >>> fillupbyte('10111')
        '00010111'
        >>> fillupbyte('11100111')
        '11100111'
    """
    return binary.zfill(len(binary) + (8 - len(binary) % 8) % 8)


def hex2string(hex_message):
    """
    Converts a hexadecimal string to ASCII characters.

    Examples:
        >>> hex2string('61')
        'a'
        >>> hex2string('776f726c64')
        'world'
        >>> hex2string('68656c6c6f')
        'hello'
    """
    return ''.join(chr(int(hex_message[i:i+2], 16)) for i in range(0, len(hex_message), 2))


def string2hex(message):
    """
    Converts ASCII characters to a hexadecimal string.

    Examples:
        >>> string2hex('a')
        '61'
        >>> string2hex('hello')
        '68656c6c6f'
        >>> string2hex('world')
        '776f726c64'
        >>> string2hex('foo')
        '666f6f'
    """
    return ''.join(hex(ord(c))[2:].rjust(2, '0') for c in message)


def encrypt_with_power(plaintext, key):
    """
    Encrypts text using a varying power of the key.

    Examples:
        >>> encrypt_with_power('Hello',250)
        '²A|lo'
        >>> string2hex(encrypt_with_power('Hello',250))
        'b2417c6c6f'
        >>> string2hex(encrypt_with_power(hex2string('acc5522cca'),250))
        '56e1422cca'
        >>> string2hex(encrypt_with_power(hex2string('acc5522cca'),123))
        'd7dc23cd0b'
        >>> string2hex(encrypt_with_power('I love Cryptography!!!',23))
        '5e314d2ef7642142737871756e667360716978202020'
        >>> encrypt_with_power('I love Cryptography!!!',0)
        'I love Cryptography!!!'
        >>> encrypt_with_power('With key 0, it will not be changed!!!',0)
        'With key 0, it will not be changed!!!'
        >>> encrypt_with_power(encrypt_with_power('Hello',123),123)
        'Hello'
        >>> encrypt_with_power(encrypt_with_power('Cryptography',10),10)
        'Cryptography'
    """
    ret = ""
    actual_key = key
    for c in plaintext:
        actual_cipher_val = ord(c) ^ actual_key
        ret += chr(actual_cipher_val)
        actual_key = actual_key ** 2 % 256
    return ret


def encrypt_with_power2(plaintext, key, mode='encrypt'):
    """
    Encrypts or decrypts text using an evolving key.

    Examples:
        >>> encrypt_with_power2('Hello',253,'encrypt')
        'µl=Í.'
        >>> encrypt_with_power2('Hello2',131,'encrypt')
        'Ël=Í.³'
        >>> string2hex(encrypt_with_power2('Hello',250,'encrypt'))
        'b2417c00ff'
        >>> string2hex(encrypt_with_power2(hex2string('acc5522cca'),250,'encrypt'))
        '56e1427e8e'
        >>> string2hex(encrypt_with_power2(hex2string('acc5522cca'),123,'encrypt'))
        'd7dc23cd0b'
        >>> string2hex(encrypt_with_power2('I love Cryptography!!!',23,'encrypt'))
        '5e314d2ef713445331f021d52ee6151091a9f8581040'
        >>> encrypt_with_power2('I am',0,'encrypt')
        'Ii°Ì'
        >>> encrypt_with_power2(encrypt_with_power2('Hello',123,'encrypt'),123,'decrypt')
        'Hello'
        >>> encrypt_with_power2(encrypt_with_power2('Hello',234,'encrypt'),234,'decrypt')
        'Hello'
        >>> encrypt_with_power2(encrypt_with_power2('Hello',2,'encrypt'),2,'decrypt')
        'Hello'
        >>> encrypt_with_power2(encrypt_with_power2('Hello',2,'encrypt'),62,'decrypt')
        'tello'
        >>> encrypt_with_power2(encrypt_with_power2('Cryptography',10,'encrypt'),10,'decrypt')
        'Cryptography'
    """
    ret, actual_key = '', key
    for c in plaintext:
        cipher_val = ord(c) ^ actual_key
        ret += chr(cipher_val)
        actual_key = update_key(actual_key, c, ret, mode)
    return ret


def update_key(key, char, cipher_text, mode):
    """
    Updates the encryption/decryption key.
    """
    new_key = key ** 2 % 256
    if new_key in [0, 1]:
        new_key = ord(char) if mode == 'encrypt' else ord(cipher_text[-1])
    return new_key


def swap_every_second_bit(number):
    """
    Swaps every second bit in the binary representation of a number.

    Examples:
        >>> swap_every_second_bit(1)
        2
        >>> swap_every_second_bit(2)
        1
        >>> swap_every_second_bit(4)
        8
        >>> swap_every_second_bit(16)
        32
        >>> bin(swap_every_second_bit(0b1010))
        '0b101'
        >>> bin(swap_every_second_bit(0b01010110))
        '0b10101001'
    """
    bin_string = fillupbyte(bin(number)[2:])
    swapped = ''.join(c[1] + c[0]
                      for c in zip(bin_string[::2], bin_string[1::2]))
    return int(bin2hex(swapped), 16)


def encrypt_with_power_and_swap_every_second_bit(plaintext, key, mode='encrypt'):
    """
    Encrypts or decrypts text using key power and bit swapping.

    Examples:
        >>> encrypt_with_power_and_swap_every_second_bit('Hello',120,'encrypt')
        'üÚùEn'
        >>> encrypt_with_power_and_swap_every_second_bit('Hello',200,'encrypt')
        'LÚùEn'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit('Hello',250,'encrypt'))
        '7ebe8cf00f'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit(hex2string('acc5522cca'),250,'encrypt'))
        'a6eeb14e81'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit(hex2string('acc5522cca'),123,'encrypt'))
        '27d3d0fd04'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit('I love Cryptography!!!',23,'encrypt'))
        '9101bdde38ec7493f23fe119de1ad6e35155376b2373'
        >>> encrypt_with_power_and_swap_every_second_bit(encrypt_with_power_and_swap_every_second_bit('Hello',123,'encrypt'),123,'decrypt')
        'Hello'
        >>> encrypt_with_power_and_swap_every_second_bit(encrypt_with_power_and_swap_every_second_bit('Hello',234,'encrypt'),234,'decrypt')
        'Hello'
        >>> encrypt_with_power_and_swap_every_second_bit(encrypt_with_power_and_swap_every_second_bit('Hello',2,'encrypt'),2,'decrypt')
        'Hello'
        >>> encrypt_with_power_and_swap_every_second_bit(encrypt_with_power_and_swap_every_second_bit('Hello',2,'encrypt'),62,'decrypt')
        'tello'
        >>> encrypt_with_power_and_swap_every_second_bit(encrypt_with_power_and_swap_every_second_bit('Cryptography',10,'encrypt'),10,'decrypt')
        'Cryptography'
    """
    ret, actual_key = '', key
    for c in plaintext:
        cipher_val = swap_bit_and_encrypt(c, actual_key, mode)
        ret += chr(cipher_val)
        actual_key = update_key(actual_key, c, ret, mode)
    return ret


def swap_bit_and_encrypt(char, key, mode):
    """
    Applies bit swapping and encrypts/decrypts a character.
    """
    if mode == 'encrypt':
        return swap_every_second_bit(ord(char)) ^ key
    return swap_every_second_bit(ord(char) ^ key)


def encrypt_with_power_and_swap_every_second_bit_8byte(plaintext, keys, mode='encrypt'):
    """
    Encrypts or decrypts text using multiple keys with power and bit swapping.

    Examples:
        >>> key1 = [1,2,3,4,5,6,7,8]
        >>> key2 = [34,76,87,98,33,99,1,234]
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte('Hello',key1,'encrypt'))
        '85989f989a'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte(hex2string('acc5522cca'),key1,'encrypt'))
        '5dc8a218c0'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte(hex2string('acc5522cca'),key2,'encrypt'))
        '7e86f67ee4'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte(hex2string('1234123123'),key2,'encrypt'))
        '0374765032'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte(hex2string('5646234325'),key2,'encrypt'))
        '8bc544e13b'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte('I love Cryptography!!!',key1,'encrypt'))
        '87129f9bbc9c178bf8b2b9a886bf80d26184e7666302'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte("To be, or not to be, that is the question: Whether 'tis nobler in the mind to suffer",key1,'encrypt'))
        'a99d13959f1a1797e514948fa13489df8081cb7361a8f5fd98723792f1cc55bb6436fbdb722817de0d25912a15eed115f48b304cd006a278d9bbb10ddad831d68d00dab5ff01dffff3b894f9463132abddfd8a30'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte('Hello world, now I can encpryt with longer key!!',key1,'encrypt'))
        '85989f989a16bc97f998910c09b9aefb509641bfe38d71edbdda112157d6d1eaf869d5625ddb1c3ade1091531ba67c53'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte('Our goal is to test out if our algorithm working well with splitting the input.',key1,'encrypt'))
        '8eb8b2149e9995945f92ba00a1bb21f8fba3e930eeaad96457eab1bf5bc4d1021d32dede57c115ff7c2a1e9016a7f55a809af5ddf771fb1798d53132095de1d1cc17dce8a139c58b80ff1c19dbccbc'
        >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Hello',key1,'encrypt'),key1,'decrypt')
        'Hello'
        >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Hello',key2,'encrypt'),key2,'decrypt')
        'Hello'
        >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Hello',key1,'encrypt'),key1,'decrypt')
        'Hello'
        >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Hello',key1,'encrypt'),key2,'decrypt'))
        '5be8c4f577'
        >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Cryptography',key1,'encrypt'),key1,'decrypt')
        'Cryptography'
        >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte("To be, or not to be, that is the question: Whether 'tis nobler in the mind to suffer",key1,'encrypt'),key1,'decrypt')
        "To be, or not to be, that is the question: Whether 'tis nobler in the mind to suffer"
        >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Hello world, now I can encpryt with longer key!!',key1,'encrypt'),key1,'decrypt')
        'Hello world, now I can encpryt with longer key!!'
        >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Our goal is to test out if our algorithm working well with joining the chunks.',key1,'encrypt'),key1,'decrypt')
        'Our goal is to test out if our algorithm working well with joining the chunks.'
    """
    result = ''
    strings = [string2hex(encrypt_with_power_and_swap_every_second_bit(
        plaintext[i::8], key, mode)) for i, key in enumerate(keys)]
    for i in range(0, len(strings[0]), 2):
        result += ''.join(s[i:i + 2] for s in strings)
    return hex2string(result)


if __name__ == "__main__":
    doctest.testmod(verbose=True)
