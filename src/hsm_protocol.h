#pragma once

#pragma pack(push,1)

enum
{
    SYMMETRIC_KEY_SIZE = 16,
    SYMMETRIC_BLOCK_SIZE = 16,
    ECC_KEY_SIZE = 32,
    HSM_MAX_MESSAGE = 4096,
    HSM_CLI_VERSION = 0x103
};

typedef struct
{
    unsigned short bytes;
} TrngArguments;

typedef struct
{
    short slot_idx;
    unsigned char user_key[16];
} KeyArguments;

typedef struct
{
    short slot_idx;
} KeyReadArguments;

enum KeyCommand
{
    HSM_KEY_GENERATE_SYMMETRIC,
    HSM_KEY_SETUP_SYMMETRIC,
    HSM_KEY_ERASE_SYMMETRIC,
    HSM_KEY_GENERATE_PRIVATE,
    HSM_KEY_SETUP_PRIVATE,
    HSM_KEY_ERASE_PRIVATE,
    HSM_KEY_READ_PUBLIC,
    HSM_KEY_READ_SYMMETRIC
};

typedef struct
{
    unsigned short data_size;
    unsigned char slot_idx;
    unsigned char flags;
} EncryptionArguments;


enum EncryptionCommand
{
    HSM_ENCRYPT,
    HSM_DECRYPT
};

enum EncryptionFlags
{
    HSM_ENCRYPTION_SETUP_IV = 1<<0,
    HSM_ENCRYPTION_CBC      = 1<<1
};

typedef struct
{
    signed char private_idx;
    unsigned char symmetric_out_idx;
    unsigned char pub[32];
} ECDHArguments;

enum ECDHCommand
{
    HSM_SETUP_SECRET
};

typedef struct
{
    unsigned char command;
} MaintenanceArguments;

enum MaintenanceCommand
{
    HSM_PROTOCOL_VERSION,
    HSM_VENDOR_ID,
    HSM_PRODUCT_ID,
    HSM_READ_SERIAL,
    HSM_HEARTBEAT,
    HSM_LEDS_STATE
};

typedef struct
{
    unsigned short data_size;
    unsigned char hash_size;
    unsigned char flags;
} HashingArguments;


enum HashingCommand
{
    HSM_HASH
};

enum HashingFlags
{
    HSM_HASHING_INIT     = 1<<0,
    HSM_HASHING_FINALIZE = 1<<1
};


typedef struct
{
  unsigned char category;
  unsigned char command;
} HsmCommand;

enum HsmCategory {
    HSM_POLL_READY,
    HSM_MAINTENANCE,
    HSM_TRNG,
    HSM_KEY,
    HSM_KEY_READ,
    HSM_ENCRYPTION,
    HSM_HASHING,
    HSM_BLOB_READ,
    HSM_ECDH
};

// KeyResponse is returned on HSM_KEY_READ request
typedef struct
{
    unsigned char length;
    unsigned char valid;
    unsigned char key[32];
} KeyResponse;

// BlobResponse is returned on HSM_BLOB_READ request
typedef struct
{
    unsigned short size;
} BlobResponse;

typedef struct
{
    unsigned char code[20];
} SerialResponse;

#pragma pack(pop)
