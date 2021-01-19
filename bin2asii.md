
## 1. represents bytes as ascii-stype hex string
将bytes在内存中的数据按照可显示的16进制字符串的形式显示出来，转换后数据长度扩展到2倍。

### in python:
```py
import binascii

test_bin1 = b'123'
test_bin2 = b'\x11\x22'
binascii.hexlify(test_bin1).decode() # '313233'
binascii.hexlify(test_bin2).decode() # '1122'
```
### in java:
```java
    public static String toHexString(byte[] arg5) {
        if(arg5 == null) {
            return null;
        }

        StringBuilder v0 = new StringBuilder("");
        int v1;
        for(v1 = 0; v1 < arg5.length; ++v1) {
            String v2 = Integer.toHexString(arg5[v1] & 0xFF);
            if(v2.length() == 1) {
                v0.append("0");
                v0.append(v2);
            }
            else {
                v0.append(v2);
            }
        }

        return v0.toString().toUpperCase(Locale.US).trim();
    }

    public static String stringToHex(String str) {
        if (str == null) {
            drt.e("HEXUtils", "stringToHex string is null");
            return "";
        }
        char[] charArray = "0123456789ABCDEF".toCharArray();
        StringBuilder sb = new StringBuilder("");
        byte[] bArr = new byte[0];
        try {
            bArr = str.getBytes("utf-8");
        } catch (UnsupportedEncodingException unused) {
            drt.a("HEXUtils", "stringToHex UnsupportedEncodingException");
        }
        for (int i = 0; i < bArr.length; i++) {
            sb.append(charArray[(bArr[i] & 240) >> 4]);
            sb.append(charArray[bArr[i] & 15]);
        }
        return sb.toString().trim();
    }

```

## 2. hex string to bytes
### in python：
```py
test_bin1 = 'aabbccdd'
bytes.fromhex(test_bin1) # b'\xaa\xbb\xcc\xdd'
```
### in java:
```java
    public static byte[] hexToBytes(String arg6) {
        if(arg6 == null) {
            return null;
        }

        arg6 = arg6.replace(" ", "");
        int v0 = arg6.length() / 2;
        byte[] v1 = new byte[v0];
        int index;
        for(index = 0; index < v0; ++index) {
            int v4 = index * 2;
            int v5 = v4 + 2;
            try {
                v1[index] = ((byte)Integer.parseInt(arg6.substring(v4, v5), 16));
            }
            catch(NumberFormatException e) {
                drt.a("HEXUtils", e.getMessage());
            }
        }

        return v1;
    }
```
