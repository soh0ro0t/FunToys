
1. bytes to string
python:
```py
import binascii

test_bin1 = b'123'
test_bin2 = b'\x11\x22'
binascii.hexlify(test_bin1).decode() # '313233'
binascii.hexlify(test_bin2).decode() # '1122'
```
java:
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
```

2. string to bytes
python：
```py
test_bin1 = 'aabbccdd'
bytes.fromhex(test_bin1) # b'\xaa\xbb\xcc\xdd'
```
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
            catch(NumberFormatException ) {
                drt.a("HEXUtils", new Object[]{"hexToBytes NumberFormatException"});
            }
        }

        return v1;
    }
```
