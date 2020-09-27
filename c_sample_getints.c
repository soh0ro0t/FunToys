#define BYTE_BITS 8
long long GetInt64(const unsigned char *buf, int len)
{
    if (buf == NULL) {
        return 0;
    }
    unsigned long long value = 0;
    if (len != sizeof(long long)) {
        return 0;
    }
    while (len-- > 0) {
        value = (value << BYTE_BITS) | (*(buf + len));
    }
    return (long long)value;
}

int GetInt(const unsigned char *buf, int len)
{
    if (buf == NULL) {
        return 0;
    }
    unsigned int value = 0;
    if (len != sizeof(int)) {
        return 0;
    }
    while (len-- > 0) {
        value = (value << BYTE_BITS) | (*(buf + len));
    }
    return (int)value;
}

short GetShort(const unsigned char *buf, int len)
{
    if (buf == NULL) {
        return 0;
    }
    unsigned short value = 0;
    if (len != sizeof(short)) {
        return 0;
    }
    while (len-- > 0) {
        value = (value << BYTE_BITS) | (*(buf + len));
    }
    return (short)value;
}

void PutInt32(unsigned char *buf, int len, int value)
{
    if (buf == NULL || len < sizeof(int)) {
        return;
    }
    int i;
    unsigned int var = value;
    for (i = 0; i < sizeof(int); i++) {
        buf[i] = var;
        var = var >> (BYTE_BITS);
    }
    return;
}
