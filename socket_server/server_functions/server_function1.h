#pragma once

#include "../../utils/utils.h"
#define RSA_PUB_KEY_PATH "socket_server/server_public.pem"
#define RSA_PRI_KEY_PATH "socket_server/server_private.pem"


void manage_encryption_info(SecurityKeys *keys);
void write_rsa_keys();
void load_keys(SecurityKeys *keys);
