# TLS v1.3 Handshake Analysis using Wireshark

## I. TLS v1.3 Handshake

## Client Hello

### 16. Version in Record Layer Header and Client Hello Version Field
To find the TLS version in the Record Layer Header and Client Hello Version field, use the following filter in Wireshark:

- The **Record Layer Header** version indicates the highest supported TLS version.
- The **Client Hello Version** field specifies the version the client wants to use.

### 17. First 6 Hex Digits of Client Random Number
To find the first six hex digits of the **Client Random**, use this filter:

- Look at the **Client Hello** message and extract the first six digits of the **Random field**.

### 18. First 6 Hex Digits of Session ID
To locate the **Session ID**, use:

- Extract the first six hex digits from the displayed Session ID.

### 19. Number of Cipher Suites Proposed by Client
To count the **Cipher Suites** proposed by the client, use:

- This will list all the Cipher Suites the client supports.
- Count the number of Cipher Suites listed.

### 20. Which Cipher Suites Are TLS 1.3?
To filter only **TLS 1.3 Cipher Suites**, use:

- TLS 1.3 Cipher Suites typically start with `TLS_AES` or `TLS_CHACHA20`.

### 21. Diffie-Hellman Curves Chosen by Client (Key Share Extension)
To find the **Elliptic Curve Diffie-Hellman (ECDH) parameters** in the Key Share extension, use:

- The Key Share extension will list the named curves the client supports.

### 22. Does the Client Know if the DH Curve is Supported by the Server?
The client **does not know** if the server supports its chosen curve at this stage. It will find out in the **Server Hello** response.

```c
TLSv1.3 Record Layer: Handshake Protocol: Client Hello
    Content Type: Handshake (22)
    // Record Layer Header
    Version: TLS 1.0 (0x0301)
    Length: 1810
    Handshake Protocol: Client Hello
        Handshake Type: Client Hello (1)
        Length: 1806
        // Client Hello Version: TLS 1.2 (0x0303) (part of TLS 1.3 handshake mechanism)
        Version: TLS 1.2 (0x0303)
        // Client Random
        Random: 38d4f6af7dd9576cb9f15dc2ae54d6187eb3b9553a544d2618dcc590f5299348
        Session ID Length: 32
        // Session ID
        Session ID: 39d56ae08caa00402e8e73c52857faa0ac525e2be0e4cf70b5b6a62877322492
        Cipher Suites Length: 32
        // Cipher Suites
        Cipher Suites (16 suites)
            Cipher Suite: Reserved (GREASE) (0x9a9a)
            // TLS 1.3 Cipher Suites
            Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
            Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
            Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
            // TLS 1.2 Cipher Suites
            Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
            Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
            Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
            Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
            Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
            Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
            Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
            Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
            Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
            Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
            Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
            Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
        Compression Methods Length: 1
        Compression Methods (1 method)
        Extensions Length: 1701
        Extension: Reserved (GREASE) (len=0)
        Extension: status_request (len=5)
        //  Diffie-Hellman Curves Chosen by Client
        Extension: key_share (len=1263) Unknown (4588), x25519
            Type: key_share (51)
            Length: 1263
            Key Share extension
                Client Key Share Length: 1261
                Key Share Entry: Group: Reserved (GREASE), Key Exchange length: 1
                // 1
                Key Share Entry: Group: Unknown (4588), Key Exchange length: 1216
                // 2
                Key Share Entry: Group: x25519, Key Exchange length: 32
        Extension: signature_algorithms (len=18)
        Extension: session_ticket (len=0)
        Extension: renegotiation_info (len=1)
        Extension: application_layer_protocol_negotiation (len=14)
        // Client Hello Version seport
        Extension: supported_versions (len=7) TLS 1.3, TLS 1.2
            Type: supported_versions (43)
            Length: 7
            Supported Versions length: 6
            Supported Version: Reserved (GREASE) (0x9a9a)
            Supported Version: TLS 1.3 (0x0304) // 1.3
            Supported Version: TLS 1.2 (0x0303) // 1.2
        Extension: ec_point_formats (len=2)
        Extension: encrypted_client_hello (len=282)
        Extension: psk_key_exchange_modes (len=2)
        Extension: application_settings (len=5)
        Extension: signed_certificate_timestamp (len=0)
        Extension: extended_master_secret (len=0)
        Extension: supported_groups (len=12)
        Extension: server_name (len=14) name=jct.ac.il
        Extension: compress_certificate (len=3)
        Extension: Reserved (GREASE) (len=1)
```

---

## Server Hello

### 23. Version in Record Header and Server Hello Version Field
To identify the TLS version sent by the server, use:

- Compare this with the Client Hello version field.

### 24. First 6 Hex Digits of Server Random Number
To extract the **Server Random** number, use:

- Look at the **Server Hello** message and extract the first six hex digits.

### 25. First 6 Hex Digits of Session ID and Comparison with Client Session ID
To find the **Session ID**, use:

- Compare the **Server Hello Session ID** with the **Client Hello Session ID**.
- If TLS 1.3 is used, the **Session ID is usually empty** or different, since TLS 1.3 establishes a new session.

### 26. Cipher Suite Chosen by Server
To locate the **selected Cipher Suite**, use:

- This will show the final choice made by the server.

### 27. Diffie-Hellman Curve Chosen by Server (Key Share Extension)
To find the **ECDH parameters selected by the server**, use:

- The **Server Hello** message will indicate which Diffie-Hellman curve the server selects.

```c
TLSv1.3 Record Layer: Handshake Protocol: Server Hello
    Content Type: Handshake (22)
    Version: TLS 1.2 (0x0303)
    Length: 122
    Handshake Protocol: Server Hello
        Handshake Type: Server Hello (2)
        Length: 118
        Version: TLS 1.2 (0x0303)
        Random: e5179ae02af9b3fb65a84b368bc4316173a4ad6e344d7e0ed16bc1d3c9cfed56
        Session ID Length: 32
        Session ID: 39d56ae08caa00402e8e73c52857faa0ac525e2be0e4cf70b5b6a62877322492
        Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
        Compression Method: null (0)
        Extensions Length: 46
        Extension: supported_versions (len=2) TLS 1.3
            Type: supported_versions (43)
            Length: 2
            Supported Version: TLS 1.3 (0x0304)
        Extension: key_share (len=36) x25519
            Type: key_share (51)
            Length: 36
            Key Share extension
                Key Share Entry: Group: x25519, Key Exchange length: 32
        [JA3S Fullstring: 771,4866,43-51]
        [JA3S: 15af977ce25de452b96affa2addb1036]
```

### 28. Did the Client Guess the Correct Curve? What Happens if Not?
- If the client cannot negotiate a compatible protocol version or cipher suite, the server either sends a "Handshake Failure" alert or a HelloRetryRequest. The latter is indicated by a fixed SHA-256 hash in the Server Hello's "Random" field, prompting the client to retry with adjusted key exchange parameters.
```
tls.handshake.random == CF:21:AD:74:E5:9A:61:11:BE:1D:8C:02:1E:65:B8:91:C2:A2:11:16:7A:BB:8C:5E:07:9e:09:e2:c8:a8:33:9c
```
```c
TLSv1.3 Record Layer: Handshake Protocol: Hello Retry Request
    Content Type: Handshake (22)
    Version: TLS 1.2 (0x0303)
    Length: 88
    Handshake Protocol: Hello Retry Request
        Handshake Type: Server Hello (2)
        Length: 84
        Version: TLS 1.2 (0x0303)
        // The random constant.
        Random: cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c (HelloRetryRequest magic)
        Session ID Length: 32
        Session ID: fa483917457be5a26ca524467b5b59a447d902990a4a042964e7563eb6be3491
        Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
        Compression Method: null (0)
        Extensions Length: 12
        Extension: supported_versions (len=2) TLS 1.3
        // The new algorithm he proposes
        Extension: key_share (len=2) secp384r1
            Type: key_share (51)
            Length: 2
            Key Share extensio
```

---

## Certificate

### 29. Who Holds the First Certificate? (Subject Field)
To find the subject of the first certificate:
```wireshark
tls.handshake.certificate
```
- Check the **Subject field** of the first certificate.

### 30. Who Issued the First Certificate? (Issuer Field)
To find the issuer of the first certificate:
```wireshark
tls.handshake.certificate
```
- Look at the **Issuer field** to see which Certificate Authority (CA) issued it.

### 31. Purpose of the Extension & Protocol Used
To analyze the **Extension field**, look for:
```wireshark
tls.handshake.extension
```
- It often includes **Online Certificate Status Protocol (OCSP) stapling** to check revocation status.

### 32. Who Holds the Second Certificate? (Subject Field)
To find the subject of the second certificate:
```wireshark
tls.handshake.certificate
```
- This is usually an **Intermediate CA certificate**.

### 33. Who Issued the Second Certificate? (Issuer Field)
To determine the issuer of the second certificate:
```wireshark
tls.handshake.certificate
```
- This is typically the **Root CA**, which signs the Intermediate CA certificate.

---

This markdown document provides a structured approach to analyzing a TLS 1.3 handshake in Wireshark, including packet filtering and key details in the handshake process.

