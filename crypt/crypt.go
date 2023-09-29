/*
Copyright 2023 Christos Triantafyllidis <christos.triantafyllidis@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package crypt

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type SignedMessage struct {
	Signature []byte `json:"signature"`
	HashSum   []byte `json:"hash_sum"`
	Message   []byte `json:"message"`
}

type EncryptedMessage struct {
	EncryptedKey []byte `json:"encrypted_key"`
	Message      []byte `json:"message"`
}

type cryptKey struct {
	Type string `json:"type"`
	Key  []byte `json:"key"`
}

type PrivateKey struct {
	initialized bool `default:"false"`
	privateKey  rsa.PrivateKey
}

type PublicKey struct {
	initialized bool `default:"false"`
	publicKey   rsa.PublicKey
}

func random_bytes(size int) ([]byte, error) {
	rnd_bytes := make([]byte, size)

	if _, err := io.ReadFull(rand.Reader, rnd_bytes); err != nil {
		return nil, err
	}
	return rnd_bytes, nil
}

func (pk *PrivateKey) create_key(keyfile string) error {
	var key cryptKey
	privkey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	key.Type = "rsa"
	key.Key = x509.MarshalPKCS1PrivateKey(privkey)

	file, err := os.OpenFile(keyfile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(key)

	return err
}

func (pk *PrivateKey) load_key(keyfile string) error {
	var key cryptKey

	if pk.initialized {
		return error(nil)
	}

	jsonKey, err := os.Open(keyfile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pk.create_key(keyfile)
		}
		return fmt.Errorf("cannot open the key file '%v'", keyfile)
	}

	byteKey, _ := io.ReadAll(jsonKey)
	json.Unmarshal(byteKey, &key)

	if key.Type != "rsa" {
		return fmt.Errorf("key type '%v' is not implemented", key.Type)
	}

	privkey, err := x509.ParsePKCS1PrivateKey(key.Key)
	if err != nil {
		return err
	}
	pk.privateKey = *privkey

	return error(nil)
}

func (pk *PrivateKey) Init(keyfile string) error {
	err := pk.load_key(keyfile)
	if err == nil {
		pk.initialized = true
	}
	return err
}

func (pk *PrivateKey) Sign(data []byte) ([]byte, error) {
	var message SignedMessage
	var err error

	if !pk.initialized {
		return nil, errors.New("crypt not initialized")
	}

	message.Message = data

	msgHash := sha512.New()
	if _, err = msgHash.Write(message.Message); err != nil {
		return nil, err
	}

	message.HashSum = msgHash.Sum(nil)

	if message.Signature, err = rsa.SignPSS(rand.Reader, &pk.privateKey, crypto.SHA512, message.HashSum, nil); err != nil {
		return nil, err
	}

	return json.Marshal(message)
}

func (pk *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	var message EncryptedMessage
	var aes_cipher cipher.Block
	var encryption_key []byte
	var gcm cipher.AEAD
	var nonce []byte
	var err error

	if !pk.initialized {
		return nil, errors.New("crypt not initialized")
	}

	if err = json.Unmarshal(data, &message); err != nil {
		return nil, err
	}

	if encryption_key, err = rsa.DecryptOAEP(sha512.New(), rand.Reader, &pk.privateKey, message.EncryptedKey, nil); err != nil {
		return nil, err
	}

	if aes_cipher, err = aes.NewCipher(encryption_key); err != nil {
		return nil, err
	}

	if gcm, err = cipher.NewGCM(aes_cipher); err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	nonce, ciphertext := message.Message[:nonceSize], message.Message[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (pk *PrivateKey) PublicKey() []byte {
	return x509.MarshalPKCS1PublicKey(&pk.privateKey.PublicKey)
}

func (pk *PublicKey) load_key(key []byte) error {
	pubkey, err := x509.ParsePKCS1PublicKey(key)
	if err != nil {
		return err
	}
	pk.publicKey = *pubkey

	return error(nil)
}

func (pk *PublicKey) Init(key []byte) error {
	err := pk.load_key(key)
	if err == nil {
		pk.initialized = true
	}
	return err
}

func (pk *PublicKey) Verify(data []byte) bool {
	var message SignedMessage
	var err error

	if err = json.Unmarshal(data, &message); err != nil {
		return false
	}

	if err = rsa.VerifyPSS(&pk.publicKey, crypto.SHA512, message.HashSum, message.Signature, nil); err != nil {
		return false
	}

	return true
}

func (pk *PublicKey) Encrypt(data []byte) ([]byte, error) {
	var message EncryptedMessage
	var aes_cipher cipher.Block
	var encryption_key []byte
	var gcm cipher.AEAD
	var nonce []byte
	var err error

	if !pk.initialized {
		return nil, errors.New("crypt not initialized")
	}

	if encryption_key, err = random_bytes(32); err != nil {
		return nil, err
	}

	if message.EncryptedKey, err = rsa.EncryptOAEP(sha512.New(), rand.Reader, &pk.publicKey, encryption_key, nil); err != nil {
		return nil, err
	}

	if aes_cipher, err = aes.NewCipher(encryption_key); err != nil {
		return nil, err
	}

	if gcm, err = cipher.NewGCM(aes_cipher); err != nil {
		return nil, err
	}

	if nonce, err = random_bytes(gcm.NonceSize()); err != nil {
		return nil, err
	}

	message.Message = gcm.Seal(nonce, nonce, data, nil)

	return json.Marshal(message)
}
