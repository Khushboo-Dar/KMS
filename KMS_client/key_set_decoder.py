from .auth_response_0x93 import parse_authentication_response

def decode_key_sets(packet):
    return parse_authentication_response(packet)
