/**************************************************
 *                                                *
 *      Skudo OÜ HSM command line interface       *
 *                                                *
 *          Version 1.3 February 20 2020          *
 *              Copyright Skudo OÜ                *
 *                                                *
 **************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>

#include <limits.h>

#include "hsm_protocol.h"

const char* spi_devname = "/dev/spidev0.0";
int spi_fd;

const char* prog_name;
char filename[1024];
int filename_given = 0;
int in_filename_given = 0;

char in_filename[1024];
int use_stdout = 0;

unsigned char key[32];
char key_filename[1024];
int key_given = 0;

unsigned char iv[SYMMETRIC_BLOCK_SIZE + 1] = {0};
int use_cbc = 0;

int command = 0;
int rng_length = 16;
int key_idx = 0;
int keypair_idx = 0;
int erase_idx = 0;
int hash_size = 16;
int leds_status = 0;

uint8_t mode = SPI_MODE_0;
uint8_t bits = 8;
uint32_t speed = 3000000;

unsigned char request_buf[128];

static void print_usage(const char *prog);


// read request won't supply any data, but expect immediate response with data
int request_read_size(int arguments_size)
{
    int size = sizeof(HsmCommand) + arguments_size;
    request_buf[size] = 0; // extra byte for lag compensation
    return size + 1; // +1 byte for spi report lag compensation
}

// in general request might supply additional data, so can't insert +1 byte for spi lag compensation
int request_size(int arguments_size)
{
    return sizeof(HsmCommand) + arguments_size;
}

int serialize_poll_request()
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_POLL_READY;
    return request_read_size(4);
}

int serialize_trng_request(int bytes)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_TRNG;
    TrngArguments* trng = (TrngArguments*)(request_buf + sizeof(HsmCommand));
    trng->bytes = bytes;
    return request_read_size(sizeof(TrngArguments));
}

int serialize_key_request(int slot, int private, int generate, unsigned char* user_key)
{
    int symmetric_action = generate ? HSM_KEY_GENERATE_SYMMETRIC : HSM_KEY_SETUP_SYMMETRIC;

    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_KEY;
    cmd->command = private ? HSM_KEY_GENERATE_PRIVATE : symmetric_action;

    KeyArguments* key = (KeyArguments*)(request_buf + sizeof(HsmCommand));
    key->slot_idx = slot;
    if(user_key)
        memcpy(key->user_key, user_key, sizeof key->user_key);

    return request_size(sizeof(KeyArguments));
}

int serialize_get_key(int slot, int public)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_KEY_READ;
    cmd->command = public ? HSM_KEY_READ_PUBLIC : HSM_KEY_READ_SYMMETRIC;
    KeyReadArguments* key = (KeyReadArguments*)(request_buf + sizeof(HsmCommand));
    key->slot_idx = slot;
    return request_read_size(sizeof(KeyReadArguments));
}

int serialize_ecdh_setup(int private_idx, int symmetric_idx, unsigned char* public)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_ECDH;
    cmd->command = HSM_SETUP_SECRET;
    ECDHArguments* key = (ECDHArguments*)(request_buf + sizeof(HsmCommand));
    key->private_idx = private_idx;
    key->symmetric_out_idx = symmetric_idx;
    memcpy(key->pub, public, sizeof key->pub);
    return request_size(sizeof(ECDHArguments));
}

int serialize_encryption(int command, int slot_idx, int flags, const unsigned char* iv, unsigned char* data, unsigned data_size)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_ENCRYPTION;
    cmd->command = command;
    EncryptionArguments* cipher = (EncryptionArguments*)(request_buf + sizeof(HsmCommand));
    cipher->slot_idx = slot_idx;
    cipher->flags = flags;
    cipher->data_size = data_size;

    if((flags & HSM_ENCRYPTION_SETUP_IV) && iv)
    {
        memcpy(request_buf + sizeof(HsmCommand) + sizeof(EncryptionArguments), iv, SYMMETRIC_BLOCK_SIZE);
    }
    return request_size(sizeof(EncryptionArguments) + (flags & HSM_ENCRYPTION_SETUP_IV ? SYMMETRIC_BLOCK_SIZE : 0));
}

int serialize_hashing(int init, int finalize, unsigned size)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_HASHING;
    cmd->command = HSM_HASH;
    HashingArguments* h = (HashingArguments*)(request_buf + sizeof(HsmCommand));
    h->data_size = size;
    h->hash_size = init;
    h->flags = (init ? HSM_HASHING_INIT : 0) | (finalize ? HSM_HASHING_FINALIZE : 0);
    return request_size(sizeof(HashingArguments));
}

int serialize_heartbeat(int state)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_MAINTENANCE;
    cmd->command = HSM_HEARTBEAT;
    MaintenanceArguments* h = (MaintenanceArguments*)(request_buf + sizeof(HsmCommand));
    h->command = state;
    return request_size(sizeof(MaintenanceArguments));
}

int serialize_leds(int state)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_MAINTENANCE;
    cmd->command = HSM_LEDS_STATE;
    MaintenanceArguments* h = (MaintenanceArguments*)(request_buf + sizeof(HsmCommand));
    h->command = state;
    return request_size(sizeof(MaintenanceArguments));
}

int serialize_read_blob(int buf_size)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_BLOB_READ;
    cmd->command = 0;
    return request_read_size(0);
}

int serialize_get_string(int code)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_MAINTENANCE;
    cmd->command = code;
    return request_read_size(0);
}

int serialize_erase_key(int _private, int slot)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_KEY;
    cmd->command = _private ? HSM_KEY_ERASE_PRIVATE: HSM_KEY_ERASE_SYMMETRIC;

    KeyArguments* key = (KeyArguments*)(request_buf + sizeof(HsmCommand));
    key->slot_idx = slot;

    return request_size(sizeof(KeyArguments));
}

void pabort(const char *s)
{
    perror(s);
    abort();
}

int get_random_bytes(int total, const char* out_filename)
{
    unsigned char buf[0x800];
    int rfile = use_stdout ? 1 : open(out_filename, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(rfile == -1)
    {
        printf("Can't create output file %s\n", out_filename);
        pabort("error");
    }
    while(total)
    {
        int bytes = total < 0x800 ? total : 0x800;
        int len = serialize_trng_request(bytes);

        struct spi_ioc_transfer tr[] =
        {
            {
                .tx_buf = (unsigned long)request_buf,
                .rx_buf = 0,
                .len = len,
                .delay_usecs = 0,
                .speed_hz = speed,
                .bits_per_word = bits,
                .cs_change = 0
            },
            {
                .tx_buf = 0,
                .rx_buf = (unsigned long)buf,
                .len = bytes,
                .delay_usecs = 0,
                .speed_hz = speed,
                .bits_per_word = bits,
                .cs_change = 0
            }
        };
        int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(2), tr);
        if (ret < 1)
            pabort("can't send spi message");

        write(rfile, buf, bytes);
        total -= bytes;
    }

    if(rfile != 1)
        close(rfile);
    return 0;
}

int poll_ready()
{
    int len = serialize_poll_request();

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = (unsigned long)request_buf,
            .len = len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), tr);
    if (ret < 1)
        pabort("can't send spi message");
    return request_buf[len - 1];
}

int wait_ready()
{
    int tests = 1;
    while(!poll_ready())
    {
        if(++tests > 10000 * 100)
            pabort("Device is not responding");
    }
    //printf("hsm ready after %d polls\n", tests);
    return tests;
}


int erase_key(int slot, int _private)
{
    int len = serialize_erase_key(_private, slot);

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = 0,
            .len = len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
            .cs_change = 0
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), tr);
    if (ret < 1)
        pabort("can't send spi message");

    return ret;
}

int setup_key(int slot, int private, int generate, unsigned char* user_key)
{
    int len = serialize_key_request(slot, private, generate, user_key);

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = 0,
            .len = len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
            .cs_change = 0
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), tr);
    if (ret < 1)
        pabort("can't send spi message");

    return 0;
}

int read_key(int slot, int public, KeyResponse* key_buf)
{
    unsigned char buf[256];
    int len = serialize_get_key(slot, public);

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = (unsigned long)buf,
            .len = len + sizeof(KeyResponse),
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
            .cs_change = 0
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), tr);
    if (ret < 1)
        pabort("can't send spi message");

    memcpy(key_buf, buf + len, sizeof(KeyResponse));

    return 0;
}

int read_string(int code, char* buf, size_t buf_len)
{

    int len = serialize_get_string(code);

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = 0,
            .len = len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
            .cs_change = 0
        },
        {
            .tx_buf = 0,
            .rx_buf = (unsigned long)buf,
            .len = buf_len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(2), tr);
    if (ret < 1)
        pabort("can't send spi message");

    return 0;
}

int setup_ecdh_key(int private_idx, int symmetric_idx, unsigned char* pub)
{
    int len = serialize_ecdh_setup(private_idx, symmetric_idx, pub);

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = 0,
            .len = len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
            .cs_change = 0
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), tr);
    if (ret < 1)
        pabort("can't send spi message");

    return 0;
}

int perform_encryption(int command, int slot, int with_cbc, const unsigned char* iv, unsigned char* data, unsigned size)
{
    int flags = with_cbc ? HSM_ENCRYPTION_CBC : 0;

    if(with_cbc && iv)
        flags |= HSM_ENCRYPTION_SETUP_IV;

    int len = serialize_encryption(command, slot, flags, iv, data, size);

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = 0,
            .len = len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
            .cs_change = 0
        },
        {
            .tx_buf = (unsigned long)data,
            .rx_buf = 0,
            .len = size,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(2), tr);
    if (ret < 1)
        pabort("can't send spi message");

    return 0;
}

int encrypt_block(int slot, int with_cbc, const unsigned char* setup_iv, unsigned char* data, unsigned size)
{
    return perform_encryption(HSM_ENCRYPT, slot, with_cbc, setup_iv, data, size);
}

int decrypt_block(int slot, int with_cbc, const unsigned char* setup_iv, unsigned char* data, unsigned size)
{
    return perform_encryption(HSM_DECRYPT, slot, with_cbc, setup_iv, data, size);
}

int hash_block(int init, int finalize, unsigned char* data, unsigned size)
{
    int len = serialize_hashing(init, finalize, size);

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = 0,
            .len = len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
            .cs_change = 0
        },
        {
            .tx_buf = (unsigned long)data,
            .rx_buf = 0,
            .len = size,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(2), tr);
    if (ret < 1)
        pabort("can't send spi message");

    return 0;
}

int set_hearbeat(int status)
{
    int len = serialize_heartbeat(status);

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = 0,
            .len = len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
            .cs_change = 0
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), tr);
    if (ret < 1)
        pabort("can't send spi message");

    return 0;
}

int user_leds(int status)
{
    int len = serialize_leds(status);

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = 0,
            .len = len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
            .cs_change = 0
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), tr);
    if (ret < 1)
        pabort("can't send spi message");

    return 0;
}

int read_blob(unsigned char* buf, unsigned buf_size)
{
    int len = serialize_read_blob(buf_size);

    struct spi_ioc_transfer tr[] =
    {
        {
            .tx_buf = (unsigned long)request_buf,
            .rx_buf = 0,
            .len = len,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
            .cs_change = 0
        },
        {
            .tx_buf = 0,
            .rx_buf = (unsigned long)buf,
            .len = buf_size,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
        }
    };
    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(2), tr);
    if (ret < 1)
        pabort("can't send spi message");

    return 0;
}


int open_device()
{
    int fd = open(spi_devname, O_RDWR);

    if (fd == -1)
        pabort("can't open spi device");

    int ret = ioctl(fd, SPI_IOC_WR_MODE, &mode);
    if (ret == -1)
        pabort("can't set spi mode");

    ret = ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    if (ret == -1)
        pabort("can't set bits per word");

    ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
    if (ret == -1)
        pabort("can't set max speed hz");

    return fd;
}

void check_command(int c)
{
    if(command)
    {
        printf("Extra command '%c' specified\n", c);
        return print_usage(prog_name);
    }
    command = c;
}

int slot_idx(const char* arg)
{
    int idx = atoi(arg);
    if(idx < 0 || idx > 3)
    {
        printf("Invalid key index %d specified\n", idx);
        exit(1);
    }
    return idx % 4;
}

void output_key(int idx, int space)
{
    KeyResponse key;
    read_key(idx, space, &key);

    if(!use_stdout && !filename_given)
    {
        // print human readable hex
        for(int i = 0; i < key.length; ++i)
            printf("%02x", key.key[i]);
        printf("\n");
        return;
    }

    // dump into file
    int fd = use_stdout ? 1 : open(filename, O_CREAT | O_TRUNC | O_RDWR, S_IREAD | S_IWRITE);
    if(fd == -1)
        pabort("Can't create file");
    write(fd, key.key, key.length);
    if(fd != 1)
        close(fd);
}

void load_keyfile(int size)
{
    if(!key_given)
    {
        printf("No key file given\n");
        exit(1);
    }

    int fd = open(key_filename, O_RDONLY);
    if(fd == -1)
        pabort("Can't open key file\n");
    int len = read(fd, key, size);
    if(len != size)
    {
        printf("Invalid key length\n");
        exit(1);
    }
    close(fd);
}

#define RPI_BUFFER_SIZE 3072

unsigned char file_buffer[RPI_BUFFER_SIZE + sizeof(BlobResponse)];

void encrypt_file()
{
    if(!in_filename_given)
    {
        printf("No input file name given!\n");
        exit(1);
    }

    if(!use_stdout && !filename_given)
    {
        printf("No output file specified!\n");
        exit(1);
    }

    int in_fd = open(in_filename, O_RDONLY);
    if(in_fd == -1)
    {
        printf("Can't open input file!\n");
        exit(1);
    }

    int out_fd = use_stdout ? 1 : open(filename, O_CREAT | O_TRUNC | O_WRONLY, S_IREAD | S_IWRITE);
    if(out_fd == -1)
        pabort("Can't create output file\n");


    int file_len = lseek(in_fd, 0, SEEK_END);
    lseek(in_fd, 0, SEEK_SET);

    write(out_fd, &file_len, sizeof file_len);

    unsigned char *setup_iv = use_cbc ? iv : 0;

    BlobResponse* blob = (BlobResponse*)file_buffer;

    while(file_len)
    {
        int block_len = file_len < RPI_BUFFER_SIZE ? file_len : RPI_BUFFER_SIZE;

        if(block_len)
        {
            block_len = read(in_fd, file_buffer, block_len);
            encrypt_block(key_idx, use_cbc, setup_iv, file_buffer, block_len);
            setup_iv = 0;
            wait_ready();
            read_blob(file_buffer, RPI_BUFFER_SIZE + sizeof(BlobResponse));
            write(out_fd, file_buffer + sizeof(BlobResponse), blob->size);
            file_len -= block_len;
        }
    }

    if(out_fd != 1)
        close(out_fd);

    close(in_fd);
}

void decrypt_file()
{
    if(!in_filename_given)
    {
        printf("No input file name given!\n");
        exit(1);
    }

    if(!use_stdout && !filename_given)
    {
        printf("No output file specified!\n");
        exit(1);
    }

    int in_fd = open(in_filename, O_RDONLY);
    if(in_fd == -1)
    {
        printf("Can't open input file!\n");
        exit(1);
    }

    int out_fd = use_stdout ? 1 : open(filename, O_CREAT | O_TRUNC | O_WRONLY, S_IREAD | S_IWRITE);
    if(out_fd == -1)
        pabort("Can't create output file\n");


    int file_len = lseek(in_fd, 0, SEEK_END);
    lseek(in_fd, 0, SEEK_SET);
    if(file_len < 20)
    {
        printf("Invalid input file\n");
        exit(1);
    }

    int source_len = 0;
    read(in_fd, &source_len, sizeof source_len);
    file_len -= sizeof source_len;

    if(source_len < 1 || file_len < source_len)
    {
        printf("Invalid input file\n");
        exit(1);
    }

    unsigned char *setup_iv = use_cbc ? iv : 0;

    BlobResponse* blob = (BlobResponse*)file_buffer;

    while(source_len && file_len)
    {
        int block_len = file_len < RPI_BUFFER_SIZE ? file_len : RPI_BUFFER_SIZE;

        if(block_len)
        {
            block_len = read(in_fd, file_buffer, block_len);
            decrypt_block(key_idx, use_cbc, setup_iv, file_buffer, block_len);
            setup_iv = 0;
            wait_ready();
            read_blob(file_buffer, RPI_BUFFER_SIZE + sizeof(BlobResponse));
            int out_len = source_len < blob->size ? source_len : blob->size;
            write(out_fd, file_buffer + sizeof(BlobResponse), out_len);

            file_len -= block_len;
            source_len -= out_len;
        }
    }

    if(out_fd != 1)
        close(out_fd);

    close(in_fd);
}

void hash_file()
{
    if(!in_filename_given)
    {
        printf("No input file name given!\n");
        exit(1);
    }

    int in_fd = open(in_filename, O_RDONLY);
    if(in_fd == -1)
    {
        printf("Can't open input file!\n");
        exit(1);
    }

    int file_len = lseek(in_fd, 0, SEEK_END);
    lseek(in_fd, 0, SEEK_SET);

    BlobResponse* blob = (BlobResponse*)file_buffer;
    int init = hash_size;
    while(file_len)
    {
        int block_len = file_len < RPI_BUFFER_SIZE ? file_len : RPI_BUFFER_SIZE;

        if(block_len)
        {
            block_len = read(in_fd, file_buffer, block_len);
            hash_block(init, block_len == file_len, file_buffer, block_len);
            wait_ready();
            file_len -= block_len;
            init = 0;
        }
    }

    read_blob(file_buffer, RPI_BUFFER_SIZE + sizeof(BlobResponse));

    close(in_fd);

    unsigned char* p = file_buffer + sizeof(BlobResponse);
    for(int i = 0; i < blob->size; ++i)
        printf("%02x", *p++);
    printf("\n");
}

void print_usage(const char *prog)
{
    printf("Skudo OÜ - HSM/FPGA chip command line interface v%d.%d\n",(HSM_CLI_VERSION>>8)&0xff,HSM_CLI_VERSION&0xff);
    printf("Usage: %s [-roSsCptgGPRredcimbLzZ]\n", prog);
    puts("  -n --rng X     generate XXX random bytes\n"
         "  -o --file filename save output to file\n"
         "  -S --stdout    output results into stdout\n"
         "  -s --speed X   max speed (Hz), default 2000000\n"
         "  -C --ecdh X    derive shared secret from secret key X [0-3] or root key\n"
         "  -k --key filename  use public key (for ECDH) or symmetric key file\n"
         "  -w --with X      target symmetrical key X [0-3] in ecdh or file encryption\n"
         "  -g --gen-sym  X  generate new symmetrical key X [0-3]\n"
         "  -G --gen-priv X  generate new keypair X [0-3]\n"
         "  -P --read-pub X  read public key from keypair X [0-3]\n"
         "  -R --root-pub    read root public key\n"
         "  -r --read-sym X  read symmetric key X [0-3]\n"
         "  -l --load-sym x  setup symmetrical key X [0-3] using keyfile given with -k\n"
         "  -e --encrypt filename  encrypt file\n"
         "  -d --decrypt filename  decypt file\n"
         "  -h --hash filename   hash the file\n"
         "  -H --hash-size x     hash length in bytes, default 16\n"
         "  -c --cbc        use cbc for encryption\n"
         "  -i --iv string  use initialization vector\n"
         "  -m --serial   read device serial/product ids\n"
         "  -b --blink x  enable or disable the hearbeat led\n"
         "  -L --leds x   set user leds status to x\n"
         "  -z --erase-sym x   wipe the symmetric key x [0-3] with zeroes\n"
         "  -Z --erase-priv x  wipe the private key x [0-3] with zeroes\n\n"
"Examples:\n\n"
"# load symmetrical key 1 from file\n"
"hsm_cli -l 1 -k keyfilename\n\n"
"# derive shared secret using private key 0 and setting symmetrical key 1 with result\n"
"hsm_cli -C 0 -w 1 -k pub_filename\n\n"
"# derive shared secret using root key and setting symmetrical key 1 with result\n"
"hsm_cli -C root -w 1 -k pub_filename\n\n"
"# encrypt file with symmetrical key 2\n"
"hsm_cli -e filename -w 2 -o encrypted_filename\n"
        );
    exit(1);
}

static void parse_opts(int argc, char *argv[])
{
    while (1) {
        static const struct option lopts[] = {
            { "speed",  1, 0, 's' },
            { "rng",    1, 0, 'n' },
            { "file",   1, 0, 'o' },
            { "stdout", 0, 0, 'S' },
            { "ecdh",   1, 0, 'C' },
            { "key",    1, 0, 'k' },
            { "with",     1, 0, 'w' },
            { "gen-sym",  1, 0, 'g' },
            { "gen-priv", 1, 0, 'G' },
            { "read-pub", 1, 0, 'P' },
            { "root-pub", 0, 0, 'R' },
            { "read-sym", 1, 0, 'r' },
            { "load-sym", 1, 0, 'l' },
            { "encrypt",  1, 0, 'e' },
            { "decrypt",  1, 0, 'd' },
            { "cbc",    0, 0, 'c' },
            { "iv",     1, 0, 'i' },
            { "serial", 0, 0, 'm' },
            { "hash", 1, 0, 'h' },
            { "hash-size", 1, 0, 'H'},
            { "leds",   1, 0, 'L'},
            { "blink",  1, 0, 'b'},
            { "erase-sym", 1, 0, 'z'},
            { "erase-priv", 1, 0, 'Z'},
            { NULL, 0, 0, 0 }
        };
        int c;

        c = getopt_long(argc, argv, "s:n:o:SC:k:w:g:G:P:Rr:l:e:d:ci:mh:H:b:L:z:Z:", lopts, NULL);

        if (c == -1)
        {
            break;
        }

        switch (c) {
            case 's':
                speed = atoi(optarg);
                if(speed < 1000) speed = 1000;
                if(speed > 3000000) speed = 3000000;
                break;
            case 'o':
                snprintf(filename, sizeof filename, "%s", optarg);
                filename_given = 1;
                break;
            case 'e':
            case 'd':
            case 'h':
                check_command(c);
                snprintf(in_filename, sizeof in_filename, "%s", optarg);
                in_filename_given = 1;
                break;
            case 'H':
                hash_size = atoi(optarg);
                break;
            case 'S':
                use_stdout = 1;
                break;
            case 'c':
                use_cbc = 1;
                break;
            case 'i':
                snprintf(iv, sizeof iv, "%s", optarg);
                break;
            case 'g':
            case 'r':
            case 'l':
                check_command(c);
            case 'w':
                key_idx = slot_idx(optarg);
                break;
            case 'n':
                check_command(c);
                rng_length = atoi(optarg);
                if(rng_length < 1 || rng_length > INT_MAX)
                {
                    printf("Invalid number of bytes requested!\n");
                    exit(1);
                }
                break;
            case 'k':
                snprintf(key_filename, sizeof key_filename, "%s", optarg);
                key_given = 1;
                break;
            case 'C':
                check_command(c);
                keypair_idx = (strcmp(optarg, "root") == 0) ? -1 : slot_idx(optarg);
                break;
            case 'G':
            case 'P':
                check_command(c);
                keypair_idx = slot_idx(optarg);
                break;
            case 'm':
            case 'R':
                check_command(c);
                break;
            case 'b':
            case 'L':
                leds_status = atoi(optarg);
                check_command(c);
                break;
            case 'z':
            case 'Z':
                erase_idx = slot_idx(optarg);
                check_command(c);
                break;
            default:
                print_usage(prog_name);
                break;
        }
    }
}


void validate_protocol()
{
    unsigned version;
    read_string(HSM_PROTOCOL_VERSION, (char*)&version, sizeof version);

    if(version != HSM_CLI_VERSION)
    {
        printf("Version: %x\n", version);
        printf("Procotol version mismatch.\n");
        printf("This hsm_cli is using protocol %d.%d, while device is reporting %d.%d\n",(HSM_CLI_VERSION>>8)&0xff,HSM_CLI_VERSION&0xff,(version>>8)&0xff, version&0xff);
        printf("Please use matching hsm_cli version, or update the device firmware.\n");
        exit(1);
    }
}

int main(int argc, char** argv)
{
    prog_name = argv[0];
    parse_opts(argc, argv);

    if(!command)
        print_usage(prog_name);

    spi_fd = open_device();

    validate_protocol();

    switch(command)
    {
        // generate random numbers
        case 'n':
            get_random_bytes(rng_length, filename_given ? filename : "random.bits");
            break;

        // ecdh setup
        case 'C':
            load_keyfile(32);
            setup_ecdh_key(keypair_idx, key_idx, key);
            wait_ready();
            break;

        // generate symmetrical key
        case 'g':
            setup_key(key_idx, 0, 1, 0);
            wait_ready();
            break;

        // directly load symmetrical key
        case 'l':
            load_keyfile(16);
            setup_key(key_idx, 0, 0, key);
            wait_ready();
            break;

        // generate private/public keypair
        case 'G':
            setup_key(keypair_idx, 1, 1, 0);
            wait_ready();
            break;

        // read symmetrical key
        case 'r':
            output_key(key_idx, 0);
            break;

        // read public key
        case 'P':
            output_key(keypair_idx, 1);
            break;

        // read hsm root public key
        case 'R':
            output_key(-1, 1);
            break;

        case 'm':
        {
            unsigned char buf[64];

            // read vendor id
            read_string(HSM_VENDOR_ID, buf, sizeof buf);
            printf("Vendor: %s\n", buf);
            read_string(HSM_PRODUCT_ID, buf, sizeof buf);
            printf("Product: %s\n", buf);
            // read hsm serial code
            read_string(HSM_READ_SERIAL, buf, sizeof buf);
            printf("Serial: %s\n", buf);
        }
        break;

        case 'e':
            encrypt_file();
            break;
        case 'd':
            decrypt_file();
            break;
        case 'h':
            hash_file();
            break;
        case 'b':
            set_hearbeat(leds_status);
            break;
        case 'L':
            user_leds(leds_status);
            break;
        case 'z':
        case 'Z':
            erase_key(erase_idx, command == 'Z');
            break;
    }

    close(spi_fd);
    return 0;
}

