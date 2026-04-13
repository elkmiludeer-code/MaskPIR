package core

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "math/big"
    "runtime"
    "sync"
    "sync/atomic"
)

var one = big.NewInt(1)

// ErrMessageTooLong is returned when attempting to encrypt a message which is
// too large for the size of the public key.
var ErrMessageTooLong = errors.New("paillier: message too long for Paillier public key size")

// GenerateKey generates an Paillier keypair of the given bit size using the
// random source random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	// First, begin generation of p in the background.
	var p *big.Int
	var errChan = make(chan error, 1)
	go func() {
		var err error
		p, err = rand.Prime(random, bits/2)
		errChan <- err
	}()

	// Now, find a prime q in the foreground.
	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// Wait for generation of p to complete successfully.
	if err := <-errChan; err != nil {
		return nil, err
	}

	n := new(big.Int).Mul(p, q)
	pp := new(big.Int).Mul(p, p)
	qq := new(big.Int).Mul(q, q)

	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        new(big.Int).Add(n, one), // g = n + 1
		},
		p:         p,
		pp:        pp,
		pminusone: new(big.Int).Sub(p, one),
		q:         q,
		qq:        qq,
		qminusone: new(big.Int).Sub(q, one),
		pinvq:     new(big.Int).ModInverse(p, q),
		hp:        h(p, pp, n),
		hq:        h(q, qq, n),
		n:         n,
	}, nil

}

// PrivateKey represents a Paillier key.
type PrivateKey struct {
	PublicKey
	p         *big.Int
	pp        *big.Int
	pminusone *big.Int
	q         *big.Int
	qq        *big.Int
	qminusone *big.Int
	pinvq     *big.Int
	hp        *big.Int
	hq        *big.Int
	n         *big.Int
}

// PublicKey represents the public part of a Paillier key.
type PublicKey struct {
	N        *big.Int // modulus
	G        *big.Int // n+1, since p and q are same length
	NSquared *big.Int
}

func h(p *big.Int, pp *big.Int, n *big.Int) *big.Int {
	gp := new(big.Int).Mod(new(big.Int).Sub(one, n), pp)
	lp := l(gp, p)
	hp := new(big.Int).ModInverse(lp, p)
	return hp
}

func l(u *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(u, one), n)
}

// Encrypt encrypts a plain text represented as a byte array. The passed plain
// text MUST NOT be larger than the modulus of the passed public key.
func Encrypt(pubKey *PublicKey, plainText []byte) ([]byte, error) {
	c, _, err := EncryptAndNonce(pubKey, plainText)
	return c, err
}

// EncryptAndNonce encrypts a plain text represented as a byte array, and in
// addition, returns the nonce used during encryption. The passed plain text
// MUST NOT be larger than the modulus of the passed public key.
func EncryptAndNonce(pubKey *PublicKey, plainText []byte) ([]byte, *big.Int, error) {
	r, err := rand.Int(rand.Reader, pubKey.N)
	if err != nil {
		return nil, nil, err
	}

	c, err := EncryptWithNonce(pubKey, r, plainText)
	if err != nil {
		return nil, nil, err
	}

	return c.Bytes(), r, nil
}

// EncryptWithNonce encrypts a plain text represented as a byte array using the
// provided nonce to perform encryption. The passed plain text MUST NOT be
// larger than the modulus of the passed public key.
func EncryptWithNonce(pubKey *PublicKey, r *big.Int, plainText []byte) (*big.Int, error) {
	m := new(big.Int).SetBytes(plainText)
	if pubKey.N.Cmp(m) < 1 { // N < m
		return nil, ErrMessageTooLong
	}

	// c = g^m * r^n mod n^2 = ((m*n+1) mod n^2) * r^n mod n^2
	n := pubKey.N
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Mod(new(big.Int).Add(one, new(big.Int).Mul(m, n)), pubKey.NSquared),
			new(big.Int).Exp(r, n, pubKey.NSquared),
		),
		pubKey.NSquared,
	)

	return c, nil
}

// Decrypt decrypts the passed cipher text.
func Decrypt(privKey *PrivateKey, cipherText []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cipherText)
	if privKey.NSquared.Cmp(c) < 1 { // c < n^2
		return nil, ErrMessageTooLong
	}

	cp := new(big.Int).Exp(c, privKey.pminusone, privKey.pp)
	lp := l(cp, privKey.p)
	mp := new(big.Int).Mod(new(big.Int).Mul(lp, privKey.hp), privKey.p)
	cq := new(big.Int).Exp(c, privKey.qminusone, privKey.qq)
	lq := l(cq, privKey.q)

	mqq := new(big.Int).Mul(lq, privKey.hq)
	mq := new(big.Int).Mod(mqq, privKey.q)
	m := crt(mp, mq, privKey)

	return m.Bytes(), nil
}

func crt(mp *big.Int, mq *big.Int, privKey *PrivateKey) *big.Int {
	u := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(mq, mp), privKey.pinvq), privKey.q)
	m := new(big.Int).Add(mp, new(big.Int).Mul(u, privKey.p))
	return new(big.Int).Mod(m, privKey.n)
}

// AddCipher homomorphically adds together two cipher texts.
// To do this we multiply the two cipher texts, upon decryption, the resulting
// plain text will be the sum of the corresponding plain texts.
func AddCipher(pubKey *PublicKey, cipher1, cipher2 []byte) []byte {
	x := new(big.Int).SetBytes(cipher1)
	y := new(big.Int).SetBytes(cipher2)

	// x * y mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(x, y),
		pubKey.NSquared,
	).Bytes()
}

// Add homomorphically adds a passed constant to the encrypted integer
// (our cipher text). We do this by multiplying the constant with our
// ciphertext. Upon decryption, the resulting plain text will be the sum of
// the plaintext integer and the constant.
func Add(pubKey *PublicKey, cipher, constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c * g ^ x mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(c, new(big.Int).Exp(pubKey.G, x, pubKey.NSquared)),
		pubKey.NSquared,
	).Bytes()
}

// Mul homomorphically multiplies an encrypted integer (cipher text) by a
// constant. We do this by raising our cipher text to the power of the passed
// constant. Upon decryption, the resulting plain text will be the product of
// the plaintext integer and the constant.
func Mul(pubKey *PublicKey, cipher []byte, constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c ^ x mod n^2
	return new(big.Int).Exp(c, x, pubKey.NSquared).Bytes()
}

// BatchEncrypt 批量加密多个明文（并行优化）
func BatchEncrypt(pubKey *PublicKey, plainTexts [][]byte) ([][]byte, error) {
    results := make([][]byte, len(plainTexts))
    workers := runtime.NumCPU()
    var wg sync.WaitGroup
    jobs := make(chan int, len(plainTexts))
    errCh := make(chan error, 1)
    var processed int64
    step := len(plainTexts) / 100
    if step == 0 {
        step = 1
    }

    for w := 0; w < workers; w++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for i := range jobs {
                cipherText, err := Encrypt(pubKey, plainTexts[i])
                if err != nil {
                    select {
                    case errCh <- fmt.Errorf("批量加密第%d个明文失败: %v", i, err):
                    default:
                    }
                    return
                }
                results[i] = cipherText
                n := atomic.AddInt64(&processed, 1)
                if int(n)%step == 0 || int(n) == len(plainTexts) {
                    pct := int(n) * 100 / len(plainTexts)
                    fmt.Printf("[同态加密] 进度: %d%% (%d/%d)\n", pct, n, len(plainTexts))
                }
            }
        }()
    }

	for i := 0; i < len(plainTexts); i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errCh:
		return nil, err
	default:
	}
	return results, nil
}

// BatchDecrypt 批量解密多个密文（并行优化）
func BatchDecrypt(privKey *PrivateKey, cipherTexts [][]byte) ([][]byte, error) {
	results := make([][]byte, len(cipherTexts))
	workers := runtime.NumCPU()
	var wg sync.WaitGroup
	jobs := make(chan int, len(cipherTexts))
	errCh := make(chan error, 1)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				plainText, err := Decrypt(privKey, cipherTexts[i])
				if err != nil {
					select {
					case errCh <- fmt.Errorf("批量解密第%d个密文失败: %v", i, err):
					default:
					}
					return
				}
				results[i] = plainText
			}
		}()
	}

	for i := 0; i < len(cipherTexts); i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errCh:
		return nil, err
	default:
	}
	return results, nil
}

// BatchAddCipher 批量同态加法（并行优化）
func BatchAddCipher(pubKey *PublicKey, ciphers1, ciphers2 [][]byte) [][]byte {
	if len(ciphers1) != len(ciphers2) {
		return nil
	}

	results := make([][]byte, len(ciphers1))
	workers := runtime.NumCPU()
	var wg sync.WaitGroup
	jobs := make(chan int, len(ciphers1))

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = AddCipher(pubKey, ciphers1[i], ciphers2[i])
			}
		}()
	}

	for i := 0; i < len(ciphers1); i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results
}

// BatchMul 批量同态乘法
func BatchMul(pubKey *PublicKey, ciphers [][]byte, constants [][]byte) [][]byte {
	if len(ciphers) != len(constants) {
		return nil
	}

	results := make([][]byte, len(ciphers))
	for i := 0; i < len(ciphers); i++ {
		results[i] = Mul(pubKey, ciphers[i], constants[i])
	}
	return results
}

// MarshalJSON 公钥JSON序列化
func (pub *PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"n":         base64.StdEncoding.EncodeToString(pub.N.Bytes()),
		"g":         base64.StdEncoding.EncodeToString(pub.G.Bytes()),
		"n_squared": base64.StdEncoding.EncodeToString(pub.NSquared.Bytes()),
	})
}

// UnmarshalJSON 公钥JSON反序列化
func (pub *PublicKey) UnmarshalJSON(data []byte) error {
	var keyData map[string]string
	if err := json.Unmarshal(data, &keyData); err != nil {
		return err
	}

	nBytes, err := base64.StdEncoding.DecodeString(keyData["n"])
	if err != nil {
		return err
	}
	pub.N = new(big.Int).SetBytes(nBytes)

	gBytes, err := base64.StdEncoding.DecodeString(keyData["g"])
	if err != nil {
		return err
	}
	pub.G = new(big.Int).SetBytes(gBytes)

	nSquaredBytes, err := base64.StdEncoding.DecodeString(keyData["n_squared"])
	if err != nil {
		return err
	}
	pub.NSquared = new(big.Int).SetBytes(nSquaredBytes)

	return nil
}

// GobEncode 实现gob编码接口
func (pub *PublicKey) GobEncode() ([]byte, error) {
	return pub.MarshalJSON()
}

// GobDecode 实现gob解码接口
func (pub *PublicKey) GobDecode(data []byte) error {
	return pub.UnmarshalJSON(data)
}

// GobEncode 实现gob编码接口
func (priv *PrivateKey) GobEncode() ([]byte, error) {
	return priv.MarshalJSON()
}

// GobDecode 实现gob解码接口
func (priv *PrivateKey) GobDecode(data []byte) error {
	return priv.UnmarshalJSON(data)
}

// MarshalJSON 私钥JSON序列化
func (priv *PrivateKey) MarshalJSON() ([]byte, error) {
	pubKeyData, err := priv.PublicKey.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var pubKeyMap map[string]string
	if err := json.Unmarshal(pubKeyData, &pubKeyMap); err != nil {
		return nil, err
	}

	privKeyMap := map[string]string{
		"public_key": string(pubKeyData),
		"p":          base64.StdEncoding.EncodeToString(priv.p.Bytes()),
		"q":          base64.StdEncoding.EncodeToString(priv.q.Bytes()),
	}

	return json.Marshal(privKeyMap)
}

// UnmarshalJSON 私钥JSON反序列化
func (priv *PrivateKey) UnmarshalJSON(data []byte) error {
	var keyData map[string]string
	if err := json.Unmarshal(data, &keyData); err != nil {
		return err
	}

	// 反序列化公钥部分
	if err := json.Unmarshal([]byte(keyData["public_key"]), &priv.PublicKey); err != nil {
		return err
	}

	// 反序列化私钥部分
	pBytes, err := base64.StdEncoding.DecodeString(keyData["p"])
	if err != nil {
		return err
	}
	priv.p = new(big.Int).SetBytes(pBytes)

	qBytes, err := base64.StdEncoding.DecodeString(keyData["q"])
	if err != nil {
		return err
	}
	priv.q = new(big.Int).SetBytes(qBytes)

	// 重新计算其他私钥参数
	priv.pp = new(big.Int).Mul(priv.p, priv.p)
	priv.qq = new(big.Int).Mul(priv.q, priv.q)
	priv.pminusone = new(big.Int).Sub(priv.p, one)
	priv.qminusone = new(big.Int).Sub(priv.q, one)
	priv.pinvq = new(big.Int).ModInverse(priv.p, priv.q)
	priv.hp = h(priv.p, priv.pp, priv.PublicKey.N)
	priv.hq = h(priv.q, priv.qq, priv.PublicKey.N)
	priv.n = priv.PublicKey.N

	return nil
}
