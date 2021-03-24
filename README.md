# node-ecies

### Package Name : node_ecies

### Type definitions
##### key struct
```
  type ECDHPublicKey struct {
    Curve elliptic.Curve
    X     *big.Int
    Y     *big.Int
  }

  type ECDHPrivateKey struct {
    D []byte
  }
```

##### cipher data struct
##### - https://github.com/bin-y/standard-ecies/blob/master/main.js
##### - cipher data format is slightly changed
```
  /// *** cipher data structure
  /// *** parse [ iv | R | c | D ]
  // cipherData[0] ~ cipherData[15] : iv
  // cipherData[16] ~ cipherData[81] : template key
  // cipherData[82] ~ cipherData[end-32] : cipherdata
  // cipherData[end-32] ~ cipherData[end] : hmac
```

### Key APIs
#### static
##### GenerateKey() : Generate private/public keypair
```
  func GenerateKey() (*ECDHPrivateKey, *ECDHPublicKey, error) 
```

##### FromBase64ToPrivateKey() : base64 to private key struct
```  
  func FromBase64ToPrivateKey(strBase64Key string) *ECDHPrivateKey 
```

##### FromBytesToPrivateKey() : bytes to private key struct
```
  func FromBytesToPrivateKey(bytePriKey []byte) *ECDHPrivateKey
```

##### FromBase64ToPublicKey() : base64 to pubilc key struct
```
  func FromBase64ToPublicKey(strBase64Key string) *ECDHPublicKey
```

##### FromBytesToPublicKey() : bytes to public key struct
```
  func FromBytesToPublicKey(bytePubKey []byte) *ECDHPublicKey
```

##### EncryptWithBase64():
```
  func EncryptWithBase64(pub *ECDHPublicKey, plainData []byte, iv []byte) (string, error)
```

##### Encrypt():
```
  func Encrypt(pub *ECDHPublicKey, plainData []byte, iv []byte) (byteRetv []byte, errRetv error)
```

##### DecryptBase64():
```
  func DecryptBase64(pri *ECDHPrivateKey, strBase64 string) ([]byte, error)
```

##### Decrypt():
```
  func Decrypt(pri *ECDHPrivateKey, cipherData []byte) (byteRetv []byte, errRetv error)
```

#### ECDHPrivateKey
##### ToBytes() : private key struct to bytes
```  
  func (pri *ECDHPrivateKey) ToBytes() []byte
```

##### ToBase64() : private key struct to base64
```
  func (pri *ECDHPrivateKey) ToBase64() string
```

#### ECDHPublicKey
##### ToBytes() : public key struct to bytes
```
  func (pub *ECDHPublicKey) ToBytes() []byte 
```

##### ToBase64() : public key struct to base64
```
  func (pub *ECDHPublicKey) ToBase64() string 
```
