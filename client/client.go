package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

var LEASTBYTE = 10

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username  string
	PKEDecKey userlib.PrivateKeyType
	DSSignKey userlib.PrivateKeyType
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}
type File struct {
	Cur    int
	Isfile bool
	// each chunk at least 256byte
	Symkey []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// someUsefulThings()
	if len(username) == 0 {
		return nil, errors.New(strings.ToTitle("username cannot be empty"))
	}
	usernameKey, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(usernameKey)
	if ok {
		return nil, errors.New(strings.ToTitle("user already exists"))
	}
	// confidentially store password
	salt := userlib.RandomBytes(16)
	// symkey used for userdata encryption
	Userkey := userlib.Argon2Key([]byte(password), salt, 32)
	var user User
	user.Username = username
	// sign pwd integrity
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New(strings.ToTitle("key generation failed"))
	}
	userlib.KeystoreSet(username+"DS", DSVerifyKey)
	user.DSSignKey = DSSignKey
	// rsa key pair
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New(strings.ToTitle("key generation failed"))
	}
	userlib.KeystoreSet(username+"PKE", PKEEncKey)
	user.PKEDecKey = PKEDecKey
	plain_user, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	iv := userlib.RandomBytes(16)
	cipher_user := userlib.SymEnc(Userkey, iv, plain_user)
	cipher_user = append(cipher_user, salt...)
	//  256-byte RSA signature
	signature, err := userlib.DSSign(DSSignKey, cipher_user)
	if err != nil {
		return nil, errors.New(strings.ToTitle("sign failed"))
	}
	signed_user := append(cipher_user, signature...)
	userlib.DatastoreSet(usernameKey, signed_user)
	return &user, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	usernameKey, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	value, ok := userlib.DatastoreGet(usernameKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("user not exists"))
	}
	// check signature
	DSVerifyKey, ok := userlib.KeystoreGet(username + "DS")
	if !ok {
		return nil, errors.New(strings.ToTitle("verify key not found"))
	}
	signature := value[len(value)-256:]
	cipher_user := value[:len(value)-256]
	err = userlib.DSVerify(DSVerifyKey, cipher_user, signature)
	if err != nil {
		return nil, errors.New(strings.ToTitle("signature incorrect"))
	}
	salt := cipher_user[len(cipher_user)-16:]
	Userkey := userlib.Argon2Key([]byte(password), salt, 32)

	plain_user := userlib.SymDec(Userkey, cipher_user[:len(cipher_user)-16])
	err = json.Unmarshal(plain_user, &userdataptr)
	if err != nil {
		return nil, errors.New("incorrect password")
	}
	return userdataptr, nil
}
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// stroagekey存的是加密file元数据
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	signed_content, ok := userlib.DatastoreGet(storageKey)
	// PKEDecKey, ok := userlib.KeystoreGet(filename + userdata.Username)
	var file File
	if ok {
		err = userdata.PKDecodeFile(signed_content, &file)
		if err != nil {
			return err
		}
		file.Cur = 0
		file.Isfile = true
	} else {
		Contentkey := userlib.RandomBytes(16)
		file.Cur = 0
		file.Symkey = Contentkey
		file.Isfile = true
	}

	signed_content, err = userdata.SYMSignContent(content, file.Symkey)
	if err != nil {
		return err
	}

	indexKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + strconv.Itoa(file.Cur)))[:16])
	if err != nil {
		return err
	}
	userlib.DatastoreSet(indexKey, signed_content)

	if len(content) > LEASTBYTE {
		file.Cur++
		file.Isfile = false
	}
	signed_file, err := userdata.PKSignFile(file)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, signed_file)
	return nil
}
func (userdata *User) SYMDecodeContent(signed_content []byte, key []byte) (plain_content_content []byte, err error) {
	DSVerifyKey, ok := userlib.KeystoreGet(userdata.Username + "DS")
	if !ok {
		return nil, errors.New(strings.ToTitle("verify key not found"))
	}
	signature := signed_content[len(signed_content)-256:]
	encrypted_content := signed_content[:len(signed_content)-256]
	err = userlib.DSVerify(DSVerifyKey, encrypted_content, signature)
	if err != nil {
		return nil, errors.New(strings.ToTitle("signature incorrect"))
	}
	plain_content := userlib.SymDec(key, encrypted_content)
	return plain_content, nil
}

func (userdata *User) SYMSignContent(plain_file []byte, key []byte) (signed_content []byte, err error) {
	iv := userlib.RandomBytes(16)
	encrypted_content := userlib.SymEnc(key, iv, plain_file)
	signature, err := userlib.DSSign(userdata.DSSignKey, encrypted_content)
	if err != nil {
		return nil, err
	}
	signed_content = append(encrypted_content, signature...)
	return signed_content, nil
}
func (userdata *User) PKSignFile(file File) (signed_file []byte, err error) {
	plain_file, err := json.Marshal(file)
	if err != nil {
		return nil, err
	}
	PKEEncKey, ok := userlib.KeystoreGet(userdata.Username + "PKE")
	if !ok {
		return nil, errors.New(strings.ToTitle("encrypt key not found"))
	}
	encrypted_file, err := userlib.PKEEnc(PKEEncKey, plain_file)
	if err != nil {
		return nil, err
	}
	signature, err := userlib.DSSign(userdata.DSSignKey, encrypted_file)
	if err != nil {
		return nil, err
	}
	signed_file = append(encrypted_file, signature...)
	return signed_file, nil
}
func (userdata *User) PKDecodeFile(signed_content []byte, file *File) (err error) {
	DSVerifyKey, ok := userlib.KeystoreGet(userdata.Username + "DS")
	if !ok {
		return errors.New(strings.ToTitle("verify key not found"))
	}
	// check signature
	signature := signed_content[len(signed_content)-256:]
	encrypted_content := signed_content[:len(signed_content)-256]
	err = userlib.DSVerify(DSVerifyKey, encrypted_content, signature)
	if err != nil {
		return errors.New(strings.ToTitle("signature incorrect"))
	}
	// rsa key pair
	plaintext, err := userlib.PKEDec(userdata.PKEDecKey, encrypted_content)
	if err != nil {
		return err
	}
	err = json.Unmarshal(plaintext, file)
	if err != nil {
		return err
	}
	return nil
}
func (userdata *User) AppendToFile(filename string, content []byte) error {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	signed_content, ok := userlib.DatastoreGet(storageKey)
	var file File
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	if len(content) == 0 {
		return nil
	}
	// rsa key pair
	err = userdata.PKDecodeFile(signed_content, &file)
	if err != nil {
		return err
	}
	// 还是个未写入数据的文件，直接写入
	if !file.Isfile {
		signed_content, err := userdata.SYMSignContent(content, file.Symkey)
		if err != nil {
			return err
		}
		indexKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + strconv.Itoa(file.Cur)))[:16])
		if err != nil {
			return err
		}
		userlib.DatastoreSet(indexKey, signed_content)
		file.Isfile = true
		if len(content) > LEASTBYTE {
			file.Cur++
			file.Isfile = false
		}
	} else {
		// 已有数据但不满256byte，继续写入数据
		indexKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + strconv.Itoa(file.Cur)))[:16])
		if err != nil {
			return err
		}
		signed_content, ok := userlib.DatastoreGet(indexKey)
		if !ok {
			return errors.New(strings.ToTitle("file not found"))
		}

		plain_content, err := userdata.SYMDecodeContent(signed_content, file.Symkey)
		if err != nil {
			return err
		}
		plain_content = append(plain_content, content...)
		signed_content, err = userdata.SYMSignContent(plain_content, file.Symkey)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(indexKey, signed_content)
		if len(plain_content) > LEASTBYTE {
			file.Cur++
			file.Isfile = false
		}
	}
	signed_file, err := userdata.PKSignFile(file)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, signed_file)
	return nil

}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	signed_content, ok := userlib.DatastoreGet(storageKey)
	var file File
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	// rsa key pair
	err = userdata.PKDecodeFile(signed_content, &file)
	if err != nil {
		return nil, err
	}
	chunk_num := file.Cur
	if file.Isfile {
		chunk_num++
	}
	for i := 0; i < chunk_num; i++ {
		indexKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + strconv.Itoa(i)))[:16])
		if err != nil {
			return nil, err
		}
		signed_content, ok := userlib.DatastoreGet(indexKey)
		if !ok {
			return nil, errors.New(strings.ToTitle("file not found"))
		}
		plain_content, err := userdata.SYMDecodeContent(signed_content, file.Symkey)
		if err != nil {
			return nil, err
		}
		content = append(content, plain_content...)
	}
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
