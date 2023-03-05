import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * @author Hunter Sullivan
 * @netid hxs200010
 * @email hunter.sullivan@utdallas.edu
 */
public class EFS extends Utility {
    
    public static enum HashAlg {
        SHA256,
        SHA384,
        SHA512
    }
    
    /**
     *  Enum to help identify the various fields in the file. 
     */
    public static enum Field {
        USERNAME,
        SALT,
        PASSWORD_HASH,
        FEK,
        FILE_SIZE,
        PADDING,
        METADATA_DIGEST,
        CONTENT,      // this is where the file contents start in file block 0
        FILE_DIGEST,
        SECRETS       // this is effectively PASSWORD_HASH, FEK, FILE_SIZE, and PADDING
    }
    
    public static enum FieldInfo {
        POSITION,
        SIZE
    }

    // Members to set the underlying hash algorithms
    private HashAlg PASSWORD_HASH_ALG = HashAlg.SHA256;
    private HashAlg METADATA_DIGEST_ALG = HashAlg.SHA256;
    private HashAlg FILE_DIGEST_ALG = HashAlg.SHA256;
    private HashAlg PBKDF2_HASH_ALG = HashAlg.SHA256;
    
    // Members to set the size of various encryption parameters.
    private int N_USERNAME_BYTES = 128;
    private int N_SALT_BYTES = 16;
    private int N_FEK_BYTES = 16;
    private int N_LENGTH_BYTES = 4;
    private int AES_BLOCK_SIZE_BYTES = 16;
    private int N_PBDFK2_ITERATIONS = 1000;
    private int DERIVED_KEY_LENGTH = 256;    // setting to same output length of SHA

    // This will be used for faster access to metadata field positions.
    private Map<Field, Map<FieldInfo, Integer>> fieldInfoMap = new HashMap<Field, Map<FieldInfo, Integer>>();
    
    private Charset CHARACTER_SET = StandardCharsets.US_ASCII;
    private Logger logger = Logger.getLogger(EFS.class.getName()); 
    
    //////////////////////////////////////////////////////////////////////
    // BEGIN helper functions for hash algorithms.
    
    /**
     * Get the hash alg block size in bytes.
     * @param h Hash alg
     * @return number of bytes
     * @throws Exception
     */
    public int getHashBlockSize(HashAlg h) throws Exception {
        if (h == HashAlg.SHA256) {
            return 64;
        } else if (h == HashAlg.SHA384) {
            return 128;
        } else if (h == HashAlg.SHA512) {
            return 128;
        }
        throw new Exception("Unsupported hash algorithm: " + h);
    }
    
    /**
     * Get the hash alg output size in bytes.
     * @param h Hash alg
     * @return number of bytes
     * @throws Exception
     */
    public int getHashOutputSize(HashAlg h) throws Exception {
        if (h == HashAlg.SHA256) {
            return 32;
        } else if (h == HashAlg.SHA384) {
            return 48;
        } else if (h == HashAlg.SHA512) {
            return 64;
        }
        throw new Exception("Unsupported hash algorithm: " + h);
    }
    
    /**
     * Hash byte array using specific hash algorithm.
     * @param key the thing to hash
     * @param hashAlg the hash algorithm
     * @return hash byte array
     * @throws Exception
     */
    public byte[] computeHash(byte[] key, HashAlg hashAlg) throws Exception {
        if (hashAlg == HashAlg.SHA256) {
            return hash_SHA256(key);
        } else if (hashAlg == HashAlg.SHA384) {
            return hash_SHA384(key);
        } else if (hashAlg == HashAlg.SHA512) {
            return hash_SHA512(key);
        } else {
            throw new Exception("Unsupported hash alg: "+ hashAlg);
        }
    }
    
    /**
     * Hash the password.
     * @param password
     * @param salt
     * @return Hash of the password as byte array.
     */
    public byte[] getPasswordHash(String password, String salt) throws Exception {
        String message = password + salt;
        return computeHash(message.getBytes(CHARACTER_SET), PASSWORD_HASH_ALG);
    }
    
    // END helper functions for hash algorithms
    //////////////////////////////////////////////////////////////////////
    
    //////////////////////////////////////////////////////////////////////
    // BEGIN metadata access and info functions
    
    /**
     * Retrieve field from metadata.
     * @param metadata The metadata
     * @param field The field to retrieve
     * @param isEncrypted Does the metadata contain encrypted data?
     * @return The field as byte array
     */
    public byte[] getField(byte[] metadata, Field field, boolean isEncrypted) throws Exception {
        logger.fine("Retrieving " + field + " from metadata.");
        
        Map<FieldInfo, Integer> map = fieldInfoMap.get(field);
        int startIndex = map.get(FieldInfo.POSITION);
        int endIndex = startIndex + map.get(FieldInfo.SIZE);
        
        return Arrays.copyOfRange(metadata, startIndex, endIndex);
    }
    
    /**
     * Write to a metadata field.
     * @param metadata
     * @param field
     * @param contents
     */
    public void writeToField(byte[] metadata, Field field, byte[] contents) throws Exception {
        
        Map<FieldInfo, Integer> map = fieldInfoMap.get(field);
        int startIndex = map.get(FieldInfo.POSITION);
        int size = map.get(FieldInfo.SIZE);
        
        System.arraycopy(contents, 0, metadata, startIndex, size);
    }
    
    /**
     * Get the size of the secret metadata in bytes. This accounts for any padding.
     * Note, the size will depend on whether the data is encrypted or not.
     * @param isEncrypted
     * @return number of bytes
     */
    public int getSecretMetadataSize(boolean isEncrypted) throws Exception {
        int result = getHashOutputSize(PASSWORD_HASH_ALG) + N_FEK_BYTES + N_LENGTH_BYTES;
        
        if (isEncrypted)
        {
            // AES requires the message size to be a multiple of the key size.
            // Account for the extra padding
            while (result % N_FEK_BYTES != 0)
            {
                result += 1;
            }
        } 

        return result;
    }
    
    /**
     * Computes the size of the entire metadata block in bytes.
     * @param isEncrypted Whether the metadata is encrypted or not
     * @return number of bytes
     * @throws Exception
     */
    public int getMetadataSize(boolean isEncrypted) throws Exception {
        return N_USERNAME_BYTES + N_SALT_BYTES + getSecretMetadataSize(isEncrypted) + getHashOutputSize(METADATA_DIGEST_ALG);
    }
    
    /**
     * Fetch file metadata.
     * @param filename
     * @return Metadata as byte array.
     * @throws Exception
     */
    public byte[] getFileMetadata(String filename) throws FileNotFoundException, Exception {
        logger.fine("ENTRY " + filename + ".");
        dir = new File(filename);
        File file = new File(dir, "0");
        
        if (file.exists()) {
            byte[] contents = read_from_file(file);
            return Arrays.copyOfRange(contents, 0, getMetadataSize(true));
        } else {
            String msg = "Failed to retrieve metadata for file " + filename + ".";
            logger.severe(msg);
            throw new FileNotFoundException(msg);
        }
    }
    
    /**
     * Decrypt the file metadata.
     * @param metadata The file's metadata
     * @param key
     * @return Full, plaintext metadata, including header, secrets, and digest.
     */
    public byte[] decryptMetadata(byte[] metadata, byte[] key) throws Exception {
        logger.info("ENTRY");

        // Only a portion of the metadata is encrypted...
        logger.fine("Decrypting secret metadata section...");
        int startIndex = fieldInfoMap.get(Field.SECRETS).get(FieldInfo.POSITION);
        int endIndex   = startIndex + fieldInfoMap.get(Field.SECRETS).get(FieldInfo.SIZE);
        
        byte[] secrets = decryptByteArray(
                Arrays.copyOfRange(metadata, startIndex, endIndex), 
                key);
        
        // Copy to new array.
        byte[] result = new byte[getMetadataSize(true)];
        System.arraycopy(metadata, 0,        result, 0,                 startIndex);     // copy plaintext header
        System.arraycopy(secrets,  0,        result, startIndex,                  secrets.length); // copy plaintext secrets
        System.arraycopy(metadata, endIndex, result, startIndex + secrets.length, metadata.length - endIndex); // copy the remaining contents of the metadata
        
        return result;
    }
    
    /**
     * Encrypt the file metadata.
     * @param metadata The file's metadata in plaintext.
     * @param key
     * @return Full, ciphertext metadata, including header, secrets, and digest.
     */
    public byte[] encryptMetadata(byte[] metadata, byte[] key) throws Exception {
        logger.info("ENTRY");

        // Only a portion of the metadata is encrypted...
        int startIndex = fieldInfoMap.get(Field.SECRETS).get(FieldInfo.POSITION);
        int endIndex   = startIndex + fieldInfoMap.get(Field.SECRETS).get(FieldInfo.SIZE);
        
        byte[] secrets = encryptByteArray(
                Arrays.copyOfRange(metadata, startIndex, endIndex), 
                key);
        
        // Copy to new array.
        byte[] result = new byte[getMetadataSize(true)];
        System.arraycopy(metadata, 0,        result, 0,                 startIndex);     // copy plaintext header
        System.arraycopy(secrets,  0,        result, startIndex,                  secrets.length); // copy plaintext secrets
        System.arraycopy(metadata, endIndex, result, startIndex + secrets.length, metadata.length - endIndex); // copy the remaining contents of the metadata
        
        return result;
    }
    
    /**
     * Checks if the password hash matches the stored hash.
     * @param metadata Plaintext metadata.
     * @param password
     * @return true if the hashes match, false otherwise.
     */
    public boolean isCorrectPassword(byte[] metadata, String password) throws Exception {
        
        // Get salt and hash the password
        boolean isEncrypted = false;
        byte[] salt = getField(metadata, Field.SALT, true);
        byte[] passwordHash = getPasswordHash(password, new String(salt, CHARACTER_SET));
        byte[] storedPasswordHash = getField(metadata, Field.PASSWORD_HASH, isEncrypted);
        
        logger.info("Checking password...");
        if (Arrays.equals(passwordHash, storedPasswordHash)) {
            logger.info("Password is correct.");
            return true; 
        } else {
            logger.warning("Password is incorrect.");
            return false;
        }
    }
    
    /**
     * Returns the number of physical files for a given file length.
     * @param fileLength
     * @return Number of physical files
     */
    public int getNumPhysicalFiles(int fileLength) throws Exception {
        if (fileLength < 0) {
            return 1;
        }
        
        int firstFileMax = fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE);
        int extraFileMax = Config.BLOCK_SIZE - getHashOutputSize(FILE_DIGEST_ALG);
        int leftOver = fileLength - firstFileMax;
        
        if (leftOver <= 0) {
            // Can fit in the metadata physical file
            return 1;
        } else {
            // Otherwise, we need one more for every extraFileMax bytes
            return 2 + (leftOver - 1) / extraFileMax; 
        }
    }
    
    /**
     * Converts the content byteId to the file's byte ID.
     * @param byteId The content byte ID
     * @return file byte ID
     */
    public int convertToFilePosition(int byteId) throws Exception {
        int result = 0;
        
        if (byteId < fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE)) {
            // We're in the file block 0
            result = fieldInfoMap.get(Field.CONTENT).get(FieldInfo.POSITION) + byteId;
            
        } else {
            // Subtract off the first file block and mod by the max size of the other file blocks
            result = (byteId - fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE)) % (Config.BLOCK_SIZE - getHashOutputSize(FILE_DIGEST_ALG));
        }
        return result;
    }
    
    /**
     * Updates the length field, called after writing to file.
     * @param length The new length
     * @param metadata current metadata in plaintext
     */
    private void updateFileLength(int length, File root, byte[] metadata, byte[] key) throws Exception {
        File fileBlockZero = new File(root, "/0");
        byte[] contents = read_from_file(fileBlockZero);

        // Update the length field in the metadata
        writeToField(metadata, Field.FILE_SIZE, integerToBytes(length));
        
        // Encrypt it
        byte[] encryptedMetadata = encryptMetadata(metadata, key);
        System.arraycopy(encryptedMetadata, 0, contents, 0, encryptedMetadata.length);
        
        byte[] fileDigest = computeFileDigest(
                contents, 
                key);
        writeToField(contents, Field.FILE_DIGEST, fileDigest);
        
        save_to_file(contents, fileBlockZero);
    }
    
    // END metadata access and info functions
    //////////////////////////////////////////////////////////////////////
    
    //////////////////////////////////////////////////////////////////////
    // BEGIN Utility functions
    
    /**
     * Pad byte array to fixed size.
     * @param bytes
     * @param size
     * @return
     * @throws Exception
     */
    public byte[] padByteArray(byte[] bytes, int size) throws Exception {
        if (size < bytes.length) {
            throw new Exception("Cannot pad byte array to smaller size.");
        }
        if (bytes.length % size == 0) {
            return bytes;
        }
        byte[] paddedArray = new byte[size];
        System.arraycopy(bytes, 0, paddedArray, 0, bytes.length);
        return paddedArray;
    }
    
    /**
     * Generates new password salt.
     * @param length The length of the salt
     * @return Byte array ASCII-encoded
     */
    public String getNewPasswordSalt(int length) {
        int leftLimit = 33;   // character '!'
        int rightLimit = 126; // letter '~'
        
        Random random = new Random();
        StringBuilder buffer = new StringBuilder(length);
        
        for (int i = 0; i < length; i++) {
            int randomLimitedInt = leftLimit + (int) 
              (random.nextFloat() * (rightLimit - leftLimit + 1));
            buffer.append((char) randomLimitedInt);
        }
        return buffer.toString();
    }
    
    /**
     * Converts int to byte array.
     * @param x
     * @return Byte array representation.
     */
    public byte[] integerToBytes(int x) {
        return ByteBuffer.allocate(4).putInt(x).array();
    }
    
    /**
     * Converts byte array to int.
     * @param bytes
     * @return Int representation.
     */
    public int bytesToInteger(byte[] bytes) {
        return ByteBuffer.wrap(bytes).getInt(); // big-endian by default
    }
    
    /**
     * Initializes the field map.
     */
    public void initializeFieldMap() throws Exception {
        int index = 0;
        
        fieldInfoMap.put(Field.USERNAME, new HashMap<FieldInfo, Integer>());
        fieldInfoMap.get(Field.USERNAME).put(FieldInfo.POSITION, index);
        fieldInfoMap.get(Field.USERNAME).put(FieldInfo.SIZE, N_USERNAME_BYTES);
        index += N_USERNAME_BYTES;
        
        fieldInfoMap.put(Field.SALT, new HashMap<FieldInfo, Integer>());
        fieldInfoMap.get(Field.SALT).put(FieldInfo.POSITION, index);
        fieldInfoMap.get(Field.SALT).put(FieldInfo.SIZE, N_SALT_BYTES);
        index += N_SALT_BYTES;
        
        fieldInfoMap.put(Field.PASSWORD_HASH, new HashMap<FieldInfo, Integer>());
        fieldInfoMap.get(Field.PASSWORD_HASH).put(FieldInfo.POSITION, index);
        fieldInfoMap.get(Field.PASSWORD_HASH).put(FieldInfo.SIZE, getHashOutputSize(PASSWORD_HASH_ALG));
        index += getHashOutputSize(PASSWORD_HASH_ALG);
        
        fieldInfoMap.put(Field.FEK, new HashMap<FieldInfo, Integer>());
        fieldInfoMap.get(Field.FEK).put(FieldInfo.POSITION, index);
        fieldInfoMap.get(Field.FEK).put(FieldInfo.SIZE, N_FEK_BYTES);
        index += N_FEK_BYTES;
        
        fieldInfoMap.put(Field.FILE_SIZE, new HashMap<FieldInfo, Integer>());
        fieldInfoMap.get(Field.FILE_SIZE).put(FieldInfo.POSITION, index);
        fieldInfoMap.get(Field.FILE_SIZE).put(FieldInfo.SIZE, N_LENGTH_BYTES);
        index += N_LENGTH_BYTES;
        
        int padding = getSecretMetadataSize(true) - getSecretMetadataSize(false);
        fieldInfoMap.put(Field.PADDING, new HashMap<FieldInfo, Integer>());
        fieldInfoMap.get(Field.PADDING).put(FieldInfo.POSITION, index);
        fieldInfoMap.get(Field.PADDING).put(FieldInfo.SIZE, padding);
        index += padding;
        
        fieldInfoMap.put(Field.METADATA_DIGEST, new HashMap<FieldInfo, Integer>());
        fieldInfoMap.get(Field.METADATA_DIGEST).put(FieldInfo.POSITION, index);
        fieldInfoMap.get(Field.METADATA_DIGEST).put(FieldInfo.SIZE, getHashOutputSize(METADATA_DIGEST_ALG));
        index += getHashOutputSize(METADATA_DIGEST_ALG);
        
        // File digest stored in last N bytes of file
        int fileDigestSize = getHashOutputSize(FILE_DIGEST_ALG);
        fieldInfoMap.put(Field.FILE_DIGEST, new HashMap<FieldInfo, Integer>());
        fieldInfoMap.get(Field.FILE_DIGEST).put(FieldInfo.POSITION, Config.BLOCK_SIZE - fileDigestSize);
        fieldInfoMap.get(Field.FILE_DIGEST).put(FieldInfo.SIZE, fileDigestSize);
        
        fieldInfoMap.put(Field.SECRETS, new HashMap<FieldInfo, Integer>());
        fieldInfoMap.get(Field.SECRETS).put(FieldInfo.POSITION, fieldInfoMap.get(Field.PASSWORD_HASH).get(FieldInfo.POSITION));
        fieldInfoMap.get(Field.SECRETS).put(FieldInfo.SIZE, getSecretMetadataSize(true));
        
        fieldInfoMap.put(Field.CONTENT, new HashMap<FieldInfo, Integer>());
        fieldInfoMap.get(Field.CONTENT).put(FieldInfo.POSITION, index);
        fieldInfoMap.get(Field.CONTENT).put(FieldInfo.SIZE, Config.BLOCK_SIZE - getHashOutputSize(FILE_DIGEST_ALG) - index);
    }
    
    // END Utility functions
    //////////////////////////////////////////////////////////////////////
    
    //////////////////////////////////////////////////////////////////////
    // BEGIN Encryption/decryption/HMAC/Key derivation algorithms
    
    /**
     * Applys the counter mode operation to generic byte array.
     * @param sometext Plaintext or ciphertext byte array
     * @param key
     * @param iv The initialization vector. If null, will default to 0s.
     * @param counter
     * @return Ciphertext or plaintext byte array
     */
    public byte[] applyCounterModeOperation(byte[] sometext, byte[] key, byte[] iv, int counter) throws Exception {
        logger.fine("ENTRY sometext.length = " + sometext.length + " bytes, key.length = " + key.length + " bytes.");
       
        if (sometext.length <= AES_BLOCK_SIZE_BYTES) {
            throw new Exception("Cannot perform counter mode operation on text size (" + sometext.length + " <= the AES block size.");
        }
        
        // Initialize some data
        int nblocks  = 0;         // at this point nblocks will be >= 1
        int ivBytes  = 12;
        
        // Check the IV
        if (iv == null) {
            iv = new byte[ivBytes]; // defaults to 0s
            
        } else if (iv.length != ivBytes) {
            throw new Exception("The IV length (" + iv.length + ") must be equal to " + ivBytes + " bytes.");
        }
        
        // Initialize the return byte array
        if (sometext.length % AES_BLOCK_SIZE_BYTES == 0) {
            nblocks = sometext.length / AES_BLOCK_SIZE_BYTES;
        } else {
            // add one more block
            nblocks = (int) Math.ceil(1.0 * sometext.length / AES_BLOCK_SIZE_BYTES);
        }
        
        byte[] returntext = new byte[nblocks * AES_BLOCK_SIZE_BYTES];
        
        // Indexes to keep track of the sometext block
        int currentIndex = 0; 
        
        // Initialize the counter endpoints
        int counterStart = counter;
        int counterEnd = counterStart + nblocks;
        
        logger.fine("nblocks = " + nblocks + " iv.length = " + iv.length + " returntext.length = " + returntext.length);
        logger.fine("counterStart = " + counterStart + " counterEnd = " + counterEnd);
        
        // Here we go...
        for (int i = counterStart; i < counterEnd; i++) {
            
            // Compute IV||CTR_i
            byte[] ctr = ByteBuffer.allocate(4).putInt(i).array();
            byte[] concat = new byte[iv.length + ctr.length];
            
            System.arraycopy(iv, 0, concat, 0, iv.length);
            System.arraycopy(ctr, 0, concat, iv.length, ctr.length);
            
            // Encrypt IV||CTR_i
            byte[] returntextBlock = encript_AES(concat, key);
            
            // This is always true:
            //     returntextBlock.length >= sometext.length
            // 
            // First XOR the result with the current block of sometext up to the sometext.length
            int j = 0;
            for (; j < returntextBlock.length && currentIndex + j < sometext.length; j++) {
                returntext[currentIndex + j] = (byte) (returntextBlock[j] ^ sometext[currentIndex + j]);
            }
            
            // Now, finish the XOR when returntextBlock.length > sometext.length
            for (; j < returntextBlock.length; j++) {
                returntext[currentIndex + j] = (byte) (returntextBlock[j] ^ 0x00);
            }
            
            currentIndex += AES_BLOCK_SIZE_BYTES;
        }
        
        return returntext;
    }
    
    /**
     * Encrypts plaintext byte array using CTR mode
     * @param plaintext
     * @param key
     * @param iv
     * @param counter
     * @return Ciphertext byte array.
     */
    public byte[] encryptByteArray(byte[] plaintext, byte[] key, byte[] iv, int counter) throws Exception {
        logger.fine("ENTRY plaintext.length = " + plaintext.length + " bytes, key.length = " + key.length + " bytes.");
        
        if (plaintext.length <= AES_BLOCK_SIZE_BYTES) {
            logger.fine("Encrypting single block...");
            return encript_AES(plaintext, key);
        }
        
        logger.fine("Encrypting via CTR mode...");
        return applyCounterModeOperation(plaintext, key, iv, counter);
    }
    
    /**
     * Encrypts plaintext byte array using CTR mode with null IV and counter = 0.
     * @param plaintext
     * @param key
     * @return Ciphertext byte array.
     */
    public byte[] encryptByteArray(byte[] plaintext, byte[] key) throws Exception {
        return encryptByteArray(plaintext, key, null, 0);
    }
    
    /**
     * Encrypts plaintext byte array using CTR mode with null IV.
     * @param plaintext
     * @param key
     * @return Ciphertext byte array.
     */
    public byte[] encryptByteArray(byte[] plaintext, byte[] key, int counter) throws Exception {
        return encryptByteArray(plaintext, key, null, counter);
    }
    
    /**
     * Decrypts ciphertext byte array using CTR mode
     * @param ciphertext
     * @param key
     * @param iv
     * @param counter
     * @return Plaintext byte array.
     */
    public byte[] decryptByteArray(byte[] ciphertext, byte[] key, byte[] iv, int counter) throws Exception {
        logger.fine("ENTRY ciphertext.length = " + ciphertext.length + " bytes, key.length = " + key.length + " bytes.");
        
        if (ciphertext.length <= AES_BLOCK_SIZE_BYTES) {
            logger.fine("Decrypting single block...");
            return decript_AES(ciphertext, key);
        }
        
        logger.fine("Decrypting via CTR mode...");
        return applyCounterModeOperation(ciphertext, key, iv, counter);
    }
    
    /**
     * Decrypts ciphertext byte array using CTR mode with null IV and counter = 0.
     * @param ciphertext
     * @param key
     * @return
     */
    public byte[] decryptByteArray(byte[] ciphertext, byte[] key) throws Exception {
        return decryptByteArray(ciphertext, key, null, 0);
    }
    
    /**
     * Decrypts ciphertext byte array using CTR mode with null IV.
     * @param ciphertext
     * @param key
     * @param counter
     * @return
     */
    public byte[] decryptByteArray(byte[] ciphertext, byte[] key, int counter) throws Exception {
        return decryptByteArray(ciphertext, key, null, counter);
    }
    
    /**
     * Decrypt an entire file block.
     * @param id The id of the file block, e.g. 0, 1, 2, ...
     * @param ciphertext The entire file block with file contents encrypted.
     * @param key The key used in decryption.
     * @return plaintext file contents
     */
    public byte[] decryptFileBlock(int id, byte[] ciphertext, byte[] key) throws Exception {
        int startIndex = 0;
        int endIndex = 0;
        int aesCounter = 0;
        
        if (id == 0) {
            // We have metadata to subtract out
            startIndex = fieldInfoMap.get(Field.CONTENT).get(FieldInfo.POSITION);
            endIndex = startIndex + fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE);
            
        } else {
            // aesCounter = block 0 size + (id - 1) * block 1 size 
            aesCounter = fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE) + (id - 1) * fieldInfoMap.get(Field.FILE_DIGEST).get(FieldInfo.POSITION);
            endIndex = fieldInfoMap.get(Field.FILE_DIGEST).get(FieldInfo.POSITION);
        }
        
        byte[] removeme = Arrays.copyOfRange(ciphertext, startIndex, endIndex); 
        
        return decryptByteArray(
                removeme, 
                key, 
                aesCounter);
    }
    
    /**
     * Encrypt an entire file block.
     * @param id The id of the file block, e.g. 0, 1, 2, ...
     * @param plaintext The plaintext contents of the file block.
     * @param key The key used in encryption.
     * @return ciphertext file contents.
     */
    public byte[] encryptFileBlock(int id, byte[] plaintext, byte[] key) throws Exception {
        int startIndex = 0;
        int endIndex = 0;
        int aesCounter = 0;
        
        // TODO Remove me
        /*if (id == 0) {
            // We have metadata to subtract out
            startIndex = fieldInfoMap.get(Field.CONTENT).get(FieldInfo.POSITION);
            endIndex = startIndex + fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE);
            
        } else {
            // aesCounter = block 0 size + (id - 1) * block 1 size 
            aesCounter = fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE) + (id - 1) * fieldInfoMap.get(Field.FILE_DIGEST).get(FieldInfo.POSITION);
            endIndex = fieldInfoMap.get(Field.FILE_DIGEST).get(FieldInfo.POSITION);
        }*/
        
        // aesCounter = block 0 size + (id - 1) * block 1 size
        if (id != 0) {
            aesCounter = fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE) + (id - 1) * fieldInfoMap.get(Field.FILE_DIGEST).get(FieldInfo.POSITION);
        }
        
        return encryptByteArray(
                plaintext, // TODO Remove me Arrays.copyOfRange(plaintext, startIndex, endIndex), 
                key, 
                aesCounter);
    }
    
    /**
     * 
     * @param key
     * @param hashAlg
     * @param blockSize
     * @return
     */
    public byte[] computeBlockSizedKey(byte[] key, HashAlg hashAlg, int blockSize) throws Exception {
        
        if (key.length >= blockSize) {
            // Keys longer than blockSize are shortened by hashing them
            return computeHash(key, hashAlg);
            
        } else {
            // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
            // Pad key with zeros to make it blockSize bytes long
            return padByteArray(key, blockSize); 
        }
    }
    
    /**
     * Compute HMAC. This algorithm follows the spec: https://www.rfc-editor.org/rfc/rfc2104
     * @param key
     * @param message
     * @param hashAlg
     * @throws Exception
     */
    public byte[] compute_HMAC(byte[] key, byte[] message, HashAlg hashAlg) throws Exception {
        int blockSize = getHashBlockSize(hashAlg);
        byte[] blockSizedKey = computeBlockSizedKey(key, hashAlg, blockSize);
        
        byte[] okeyPad = new byte[blockSizedKey.length];
        byte[] ikeyPad = new byte[blockSizedKey.length];
        
        for (int i = 0; i < blockSizedKey.length; i++) {
            okeyPad[i] = (byte) (blockSizedKey[i] ^ 0x5c);
            ikeyPad[i] = (byte) (blockSizedKey[i] ^ 0x36);
        }
        
        // Concat ikeyPad and message
        byte[] iConcat = new byte[ikeyPad.length + message.length];
        System.arraycopy(ikeyPad, 0, iConcat, 0,              ikeyPad.length);
        System.arraycopy(message, 0, iConcat, ikeyPad.length, message.length);
        
        // Hash it
        byte[] iHash = computeHash(iConcat, hashAlg);
        
        // Concat okeyPad and iHash
        byte[] oConcat = new byte[okeyPad.length + iHash.length];
        System.arraycopy(okeyPad, 0, oConcat, 0,              okeyPad.length);
        System.arraycopy(iHash,   0, oConcat, okeyPad.length, iHash.length);
        
        // Hash it
        return computeHash(oConcat, hashAlg);
    }
    
    /**
     * Compute the internal XOR sum for PBKDF2. This corresponds to F (P, S, c, i) in the spec.
     * @param password
     * @param salt
     * @param niterations
     * @param iteration
     * @param hashAlg
     * @return
     * @throws Exception
     */
    public byte[] compute_PBKDF2_XORSUM(byte[] password, byte[] salt, int niterations, int iteration, HashAlg hashAlg) throws Exception {
        
        // Prepare salt || INT(iteration) for U_1
        int sizeOfInt = 4;
        byte[] saltConcatInt = new byte[salt.length + sizeOfInt];
        System.arraycopy(salt, 0, saltConcatInt, 0, salt.length);
        System.arraycopy(ByteBuffer.allocate(sizeOfInt).putInt(iteration).array(), 0, saltConcatInt, salt.length, sizeOfInt);
        
        // Compute U_1
        byte[] current_U = compute_HMAC(password, saltConcatInt, hashAlg); 
        
        // Prepare result
        byte[] result = current_U.clone();
        
        // Loop to compute U_2, U_3, ... , U_c
        for (int i = 1; i < niterations; i++) {
            // Compute U_i
            current_U = compute_HMAC(password, current_U, hashAlg);
            
            // Compute result XOR U_i
            for (int j = 0; j < current_U.length; j++) {
                result[j] = (byte) (result[j] ^ current_U[j]);
            }
        }
        
        return result;
    }
    
    /**
     * Compute PBKDF2 using HMAC. This algorithm follows the spec: https://www.rfc-editor.org/rfc/rfc2898#section-5.2
     * Note, this implementation requires the key size to be a multiple of the underlying hash size.  
     * @param password
     * @param salt
     * @param iterations
     * @param dkLen Bit length of the derived key.
     * @param hashAlg Hash algorithm to use with HMAC.
     * @return Derived key as byte array.
     */
    public byte[] compute_PBKDF2(byte[] password, byte[] salt, int niterations, int dkLen, HashAlg hashAlg) throws Exception {
        logger.fine("ENTRY " + niterations + " " + dkLen + " " + hashAlg);
        
        if (niterations < 0) {
            throw new Exception("Number of iterations must be greater than zero");
        }
        
        int hLenBytes = getHashOutputSize(hashAlg);
        int hLen = hLenBytes * 8;                   // must be in bits
        
        if (dkLen > (((long)1 << 32) - 1) * hLen) {
            throw new Exception("Derived key length is too long.");
        }
        
        // Force the key length to be a multiple of the hash length. 
        // This is not in the spec, but it simplifies the result.
        if (dkLen % hLen != 0) {
            throw new Exception("Derived key size must be a multiple of " + hLen + " bits.");
        }
        
        int l = (int) Math.ceil(1.0 * dkLen / hLen); // the number of hLen-bit blocks in the derived key
        int r = dkLen - (l - 1) * hLen;              // the number of bits in the last block
        
        logger.info("dkLen = " + dkLen + " hLen = " + hLen + " l = " + l + " r = " + r);
        
        // Prepare byte array for the result
        byte[] result = new byte[l * hLenBytes];
        
        // Compute T_i for blocks 1, 2, ..., l
        for (int i = 1; i <= l; i++) {
            byte[] T_i = compute_PBKDF2_XORSUM(password, salt, niterations, i, hashAlg);
            
            // Concatenate this T_i with the others
            System.arraycopy(T_i, 0, result, (i - 1) * T_i.length, T_i.length);
        }
        
        return result;
    }
    
    /**
     * Compute PBKDF2 using HMAC-SHA256.
     * @param password
     * @param salt
     * @param iterations
     * @param dkLen Bit length of derived key.
     * @return Derived key as byte array.
     */
    public byte[] compute_PBKDF2_SHA256(byte[] password, byte[] salt, int niterations, int dkLen) throws Exception {
        return compute_PBKDF2(password, salt, niterations, dkLen, HashAlg.SHA256);
    }
    
    /**
     * Compute PBKDF2 using HMAC-SHA384.
     * @param password
     * @param salt
     * @param iterations
     * @param dkLen Bit length of derived key.
     * @return Derived key as byte array.
     */
    public byte[] compute_PBKDF2_SHA384(byte[] password, byte[] salt, int niterations, int dkLen) throws Exception {
        return compute_PBKDF2(password, salt, niterations, dkLen, HashAlg.SHA384);
    }
    
    /**
     * Compute PBKDF2 using HMAC-SHA512.
     * @param password
     * @param salt
     * @param iterations
     * @param dkLen Bit length of derived key.
     * @return Derived key as byte array.
     */
    public byte[] compute_PBKDF2_SHA512(byte[] password, byte[] salt, int niterations, int dkLen) throws Exception {
        return compute_PBKDF2(password, salt, niterations, dkLen, HashAlg.SHA512);
    }
    
    /**
     * Computes the derived key.
     * @param password
     * @param salt
     * @return The derived key
     * @throws Exception
     */
    public byte[] computeDerivedKey(byte[] password, byte[] salt) throws Exception {
        return compute_PBKDF2(password, salt, N_PBDFK2_ITERATIONS, DERIVED_KEY_LENGTH, PBKDF2_HASH_ALG);
    }
    
    /**
     * Compute digest of metadata.
     * @param metadata
     * @param key
     * @return The digest of the metadata
     * @throws Exception
     */
    public byte[] computeMetadataDigest(byte[] metadata, byte[] key) throws Exception {
        return compute_HMAC(
                key, 
                Arrays.copyOfRange(metadata, 0, fieldInfoMap.get(Field.METADATA_DIGEST).get(FieldInfo.POSITION)), 
                METADATA_DIGEST_ALG);
    }
    
    /**
     * Compute digest of file.
     * @param contents
     * @param key
     * @return The digest of the metadata.
     * @throws Exception
     */
    public byte[] computeFileDigest(byte[] contents, byte[] key) throws Exception {
        return compute_HMAC(
                key, 
                Arrays.copyOfRange(contents, 0, fieldInfoMap.get(Field.FILE_DIGEST).get(FieldInfo.POSITION)), 
                FILE_DIGEST_ALG);
    }
    
    // END Encryption/decryption/HMAC/Key derivation algorithms
    //////////////////////////////////////////////////////////////////////
    
    /**
     * EFS constructor.
     * @param e
     */
    public EFS(Editor e)
    {
        super(e);
                
        try {
            // Initialize logging
            System.setProperty("java.util.logging.SimpleFormatter.format", 
                    "%1$tF %1$tT %4$s %2$s %5$s%6$s%n");
            FileHandler fh = new FileHandler("efs.log");
            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
            logger.setUseParentHandlers(false); // disable console logging
            
            logger.setLevel(Level.FINE);
            logger.getHandlers()[0].setLevel(Level.FINE);
            
        } catch (SecurityException ex) {  
            ex.printStackTrace();  
        } catch (IOException ex) {  
            ex.printStackTrace();
        }
        
        try {
            // Initialize field position map
            initializeFieldMap();
            
        } catch (Exception ex) {
            logger.severe("Failed to initialize field position map: " + ex.getMessage());
            ex.printStackTrace();
        }
        
        // Set username and password
        //set_username_password();
    }

    /**
     * Create a new file on the filesystem.
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        logger.fine("ENTRY " + file_name + " " + user_name);
        
        File metadataFile = null;
        
        try {
            logger.info("Creating new file " + file_name + " for user " + user_name + ".");
            
            dir = new File(file_name);
            if (dir.exists()) {
                logger.info("The file " + file_name + " already exists.");
                return;
            }
            
            // Create the directory for the file
            boolean dirCreated = dir.mkdir();
            if (!dirCreated) {
                String msg = "Failed to create the directory for the file " + file_name + ".";
                logger.severe(msg);
                throw new Exception(msg);
            }
        
            // This is a new file...
            
            // Metadata will be stored in first physical file.
            metadataFile = new File(dir, "0");
            
            // Initialize the byte array for this file
            byte[] toWrite = new byte[Config.BLOCK_SIZE];
            
            //################
            // Begin header section...
            
            if (user_name.length() > N_USERNAME_BYTES) {
                String msg = "Username longer than " + N_USERNAME_BYTES + " bytes.";
                logger.severe(msg);
                throw new Exception(msg);
            }
            if (password.length() > N_USERNAME_BYTES) {
                String msg = "Password longer than " + N_USERNAME_BYTES + " bytes.";
                logger.severe(msg);
                throw new Exception(msg);
            }

            // Add the username
            byte[] username = new byte[N_USERNAME_BYTES];
            System.arraycopy(user_name.getBytes(CHARACTER_SET), 0, username, 0, user_name.getBytes(CHARACTER_SET).length);
            writeToField(toWrite, Field.USERNAME, username);
            
            // Add the salt
            String salt = getNewPasswordSalt(N_SALT_BYTES);
            writeToField(toWrite, Field.SALT, salt.getBytes(CHARACTER_SET));
            
            //################
            // Begin secret section...
            
            // Store secret data into temp array so we can encrypt it
            int nEncryptedBytes = getSecretMetadataSize(true);
            byte[] secretData = new byte[nEncryptedBytes];
            
            byte[] passwordHash = getPasswordHash(password, salt);
            byte[] fek = secureRandomNumber(N_FEK_BYTES);
            byte[] fileLength = integerToBytes(0);  // We are not storing anything yet
            
            System.arraycopy(passwordHash,  0, secretData, 0,                                passwordHash.length);
            System.arraycopy(fek,           0, secretData, passwordHash.length,              fek.length);
            System.arraycopy(fileLength,    0, secretData, passwordHash.length + fek.length, fileLength.length);

            logger.fine("Deriving encryption key from password...");
            byte[] derivedKey = computeDerivedKey(password.getBytes(CHARACTER_SET), salt.getBytes(CHARACTER_SET));
            
            logger.fine("Encrypting secret metadata with derived key...");
            byte[] encryptedMetadata = encryptByteArray(secretData, derivedKey);
            
            writeToField(toWrite, Field.SECRETS, encryptedMetadata);
            
            //################
            // Begin file contents section...
            
            // Sanity check...
            int allMetadataSize = getMetadataSize(true) + getHashOutputSize(FILE_DIGEST_ALG); 
            if (allMetadataSize > Config.BLOCK_SIZE) {
                String msg = "Metadata section size (" + allMetadataSize + ") exceeds physical file size limit (" + Config.BLOCK_SIZE +")";
                logger.severe(msg);
                throw new Exception(msg);
            }

            // Encrypt empty file contents
            logger.fine("Encrypting file contents with FEK...");
            byte[] encryptedFileContents = encryptByteArray(new byte[Config.BLOCK_SIZE - allMetadataSize], fek);

            int fileContentsIndex = 
                    fieldInfoMap.get(Field.METADATA_DIGEST).get(FieldInfo.POSITION) + 
                    fieldInfoMap.get(Field.METADATA_DIGEST).get(FieldInfo.SIZE);
            System.arraycopy(encryptedFileContents, 0, toWrite, fileContentsIndex, encryptedFileContents.length);
            
            //################
            // Begin digest section...
            
            logger.fine("Computing metadata digest using derived key...");
            byte[] metadataDigest = computeMetadataDigest(toWrite, derivedKey);
            writeToField(toWrite, Field.METADATA_DIGEST, metadataDigest);
            
            logger.fine("Computing file digest using derived key...");
            byte[] fileDigest = computeFileDigest(toWrite, derivedKey);
            writeToField(toWrite, Field.FILE_DIGEST, fileDigest);
            
            logger.fine("Writing metadata to physical file...");
            save_to_file(toWrite, metadataFile);
            logger.info("Successfully created new file " + file_name + " for user " + user_name + ".");
            
        } catch (Exception e) {
            String msg = "Failed to create new file " + file_name + " for user " + user_name + ": " + e.getMessage();
            logger.severe(msg);
            
            // Remove the file and directory
            if (metadataFile != null) {
                metadataFile.delete();
            }
            dir.delete();
            
            throw e;
        }
    }

    /**
     * Get username from file metadata.
     */
    @Override
    public String findUser(String file_name) throws Exception {
        logger.fine("ENTRY " + file_name);
        
        try {
            byte[] metadata = getFileMetadata(file_name);
            byte[] usernameBytes = getField(metadata, Field.USERNAME, true);
            
            // Find the first zero byte
            int i;
            for (i = 0; i < metadata.length && metadata[i] != 0; i++) {}
            
            return new String(usernameBytes, 0, i, CHARACTER_SET);
            
        } catch (Exception e) {
            logger.severe("Failed to find user for file " + file_name + ": " + e.getMessage());
            throw e;
        }
    }

    /**
     * Computes the length of the file.
     * @param file_name 
     * @param password
     * @return the length of the file in bytes
     */
    @Override
    public int length(String file_name, String password) throws Exception {
        logger.fine("ENTRY " + file_name);
        
        try {
            byte[] metadata = getFileMetadata(file_name);
            
            // We need to decrypt the metadata so we need to authenticate the user
            byte[] salt = getField(metadata, Field.SALT, true);
            byte[] derivedkey = computeDerivedKey(password.getBytes(CHARACTER_SET), salt);
            byte[] plaintext = decryptMetadata(metadata, derivedkey);
            
            if (!isCorrectPassword(plaintext, password)) {
                throw new PasswordIncorrectException();
            }
            
            byte[] lengthBytes = getField(plaintext, Field.FILE_SIZE, false);
            int length = bytesToInteger(lengthBytes);
            
            return length;
            
        } catch (PasswordIncorrectException e) {
            logger.severe("Password incorrect.");
            throw e;
        } catch (Exception e) {
            logger.severe("Failed to find user for file " + file_name + ": " + e.getMessage());
            throw e;
        }
    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
        logger.fine("ENTRY file_name = " + file_name + " starting_position = " + starting_position + " len = " + len + ".");
        
        try {
            
            //#######################################
            // Step 1) Parse the metadata and authenticate the user
            
            byte[] metadata = getFileMetadata(file_name);
            
            // Decrypt the metadata so we can authenticate the user
            byte[] salt = getField(metadata, Field.SALT, true);
            byte[] derivedKey = computeDerivedKey(password.getBytes(CHARACTER_SET), salt);
            byte[] plaintextMetadata = decryptMetadata(metadata, derivedKey);
            byte[] fek = getField(plaintextMetadata, Field.FEK, false);

            if (!isCorrectPassword(plaintextMetadata, password)) {
                throw new PasswordIncorrectException();
            }

            // Make sure the starting position is not greater than the current file length
            int fileLength = 0;
            fileLength = bytesToInteger(getField(plaintextMetadata, Field.FILE_SIZE, false));

            if ((starting_position + len) > fileLength) {
                throw new Exception("Starting position for write (" + starting_position
                        + ") and length (" + len + ") is >= the current file length (" + fileLength + ").");
            }
            
            //#######################################
            // Step 2) Determine relevant file blocks loop over them

            // And here... we... go...
            File root = new File(file_name);
            
            // Compute the file block endpoints.
            // starting_position starts at 0, and file blocks start at 0.
            int startFileBlock = getNumPhysicalFiles(starting_position + 1) - 1;
            int endFileBlock   = getNumPhysicalFiles(starting_position + len) - 1;
            
            String result = "";
            
            for (int i = startFileBlock; i <= endFileBlock; i++) {
                
                //#######################################
                // Step 2a) Decrypt this file block 
                
                File currentFileBlock = new File(root, Integer.toString(i));
                byte[] encryptedContents = null;
                
                if (currentFileBlock.exists()) {
                    encryptedContents = read_from_file(currentFileBlock);
                }
                
                // Decrypt the file
                String temp = byteArray2String(decryptFileBlock(i, encryptedContents, fek));
                
                //#######################################
                // Step 2b) Grab the content and append to the result 
                
                // End block first is more convenient
                if (i == endFileBlock) {
                    if (i == 0) {
                        temp = temp.substring(0, starting_position + len);
                        
                    } else {
                        int fp = convertToFilePosition(starting_position + len - 1);
                        temp = temp.substring(0, fp+1);
                    }
                }
                
                if (i == startFileBlock) {
                    if (i == 0) {
                        temp = temp.substring(starting_position);
                        
                    } else {
                        temp = temp.substring(convertToFilePosition(starting_position));
                    }
                }
                
                result += temp;
            }

            return result.getBytes("UTF-8");
            
        } catch (Exception e) {
            logger.severe("Failed to read from " + file_name + ".");
            throw e;
        }
    }

    /**
     * Write new content to file. Note, this will overwrite data from the
     * starting_position to the starting position + content.length.
     * @param file_name
     * @parma starting_position Where to start writing, starts at 0.
     * @param content
     * @param password
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        logger.fine("ENTRY " + file_name + " " + starting_position + " " + content.length);
        
        try {
            
            //#######################################
            // Step 1) Parse the metadata and authenticate the user
            
            byte[] metadata = getFileMetadata(file_name);
            
            // Decrypt the metadata so we can authenticate the user
            byte[] salt = getField(metadata, Field.SALT, true);
            byte[] derivedKey = computeDerivedKey(password.getBytes(CHARACTER_SET), salt);
            byte[] plaintextMetadata = decryptMetadata(metadata, derivedKey);
            byte[] fek = getField(plaintextMetadata, Field.FEK, false);

            if (!isCorrectPassword(plaintextMetadata, password)) {
                throw new PasswordIncorrectException();
            }

            // Make sure the starting position is not greater than the current file length
            int fileLength = 0;
            fileLength = bytesToInteger(getField(plaintextMetadata, Field.FILE_SIZE, false));

            if (starting_position > fileLength) {
                throw new Exception("Starting position for write (" + starting_position
                        + ") is >= the current file length (" + fileLength + ").");
            }
            
            //#######################################
            // Step 2) Determine relevant file blocks loop over them

            // And here... we... go...
            File root = new File(file_name);
            
            // Compute the file block endpoints.
            // starting_position starts at 0, and file blocks start at 0.
            int startFileBlock = getNumPhysicalFiles(starting_position + 1) - 1;
            int endFileBlock   = getNumPhysicalFiles(starting_position + content.length) - 1;

            // How many content bytes in a file?
            int nContentBytes = Config.BLOCK_SIZE - fieldInfoMap.get(Field.FILE_DIGEST).get(FieldInfo.SIZE); 
            
            // Are we starting on a file boundary?
            // This will be used in calculating a prefix.
            boolean isStartingOnBoundary = false;
            if (starting_position == 0 || convertToFilePosition(starting_position) == 0) {
                isStartingOnBoundary = true;
            }
            
            for (int i = startFileBlock; i <= endFileBlock; i++) {
                
                //#######################################
                // Step 2a) Read the encrypted file block and initialize some properties 
                
                
                File currentFileBlock = new File(root, Integer.toString(i));
                byte[] encryptedContents = null;
                
                if (currentFileBlock.exists()) {
                    encryptedContents = read_from_file(currentFileBlock);
                }
                
                // Determine the start and end points in the content array.
                // Let's say we start in the middle of the file block and
                // write to the end of the block, but we still have some 
                // more to write. Then next time around, our starting point
                // in the content array will need to "subtract" off what
                // we wrote previously.
                
                // Note, starting_position is the content position to start writing to.
                // The sp and ep variables are the endpoints in the data to write.
                
                
                int sp = i * nContentBytes - starting_position;
                int ep = (i + 1) * nContentBytes - starting_position;
                
                // The first file has fewer available bytes for writing
                if (i == 0) {
                    ep = fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE);
                } 
                if (i != 0 && startFileBlock == 0) {
                    sp -= fieldInfoMap.get(Field.CONTENT).get(FieldInfo.POSITION);
                    ep -= fieldInfoMap.get(Field.CONTENT).get(FieldInfo.POSITION);
                }
                
                String prefix = "";  // the data before the starting point 
                String postfix = ""; // the data after the end point

                //#######################################
                // Step 2a) Decrypt the edge file blocks and calculate prefix and postfix
                
                if (i == startFileBlock) {
                    
                    // If we're at the start of a new file block, there is nothing to do.
                    if (!isStartingOnBoundary) {
                        
                        // Decrypt the file contents.
                        String temp = byteArray2String(decryptFileBlock(i, encryptedContents, fek));

                        if (i == 0) {
                            prefix = temp.substring(0, starting_position);
                            
                        } else {
                            prefix = temp.substring(0, starting_position - fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE));
                        }
                        
                        // We might have started with < 0, 
                        sp = Math.max(sp, 0);
                    }
                }
                    
                if (i == endFileBlock) {
                    
                    // If the file doesn't exist yet, this means we'll be writing a new one.
                    // In any case, there is no postfix.
                    if (currentFileBlock.exists()) {

                        // Decrypt the file
                        String temp = byteArray2String(decryptFileBlock(i, encryptedContents, fek));
                        int lastContentIndex = starting_position + content.length - 1;
                        
                        if (i != 0) {
                            lastContentIndex = convertToFilePosition(lastContentIndex);
                        }

                        if (temp.length() > lastContentIndex) {
                            postfix = temp.substring(lastContentIndex+1);
                        }
                        else {
                            postfix = "";
                        }
                    }
                    ep = Math.min(ep, content.length);
                    
                }
                
                //#######################################
                // Step 2b) Concatenate the prefix, new content, and postfix and pad to the end of the file block
                
                String newContentString = prefix + byteArray2String(Arrays.copyOfRange(content, sp, ep)) + postfix;
                
                int padding = fieldInfoMap.get(Field.FILE_DIGEST).get(FieldInfo.POSITION) - newContentString.length();
                if (i == 0) {
                    padding = fieldInfoMap.get(Field.CONTENT).get(FieldInfo.SIZE) - newContentString.length() ;
                } 

                for (int p = 0; p < padding; p++) {
                    newContentString += '\0';
                }
                
                //#######################################
                // Step 2c) Encrypt the updated file block contents and write to new array
                
                byte[] toWrite = new byte[Config.BLOCK_SIZE];
                
                byte[] newEncryptedContents = encryptFileBlock(i, newContentString.getBytes(), fek);
                
                if (i == 0) {
                    System.arraycopy(encryptedContents,    0, toWrite, 0, fieldInfoMap.get(Field.CONTENT).get(FieldInfo.POSITION)); // copy metadata
                    System.arraycopy(newEncryptedContents, 0, toWrite, fieldInfoMap.get(Field.CONTENT).get(FieldInfo.POSITION), newEncryptedContents.length); // new file contents
                    
                } else {
                    System.arraycopy(newEncryptedContents, 0, toWrite, 0, newEncryptedContents.length);
                }
                
                //#######################################
                // Step 2d) Recompute the file digest
                
                logger.fine("Computing file digest for file block " + i + " using derived key...");
                byte[] fileDigest = computeFileDigest(toWrite, derivedKey);
                writeToField(toWrite, Field.FILE_DIGEST, fileDigest);
                
                save_to_file(toWrite, currentFileBlock);
            }
            
            //#######################################
            // Step 3) Update the length field in file block 0
            int newLength = starting_position + content.length;
            if (newLength > fileLength) {
                updateFileLength(newLength, root, plaintextMetadata, derivedKey);
            }

        }
        catch (Exception e) {
            logger.severe("Failed to write content to file " + file_name + ".");
            throw e;
        }
    }

    /**
     * Check the integrity of the file.
     * @param file_name
     * @param password
     * @return false if the file has been modified, true otherwise
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        logger.fine("ENTRY " + file_name);
        
        boolean result = true;
        
        try {
            byte[] metadata = getFileMetadata(file_name);
            
            // It is worthwhile to authenticate the data before the user.
            // Otherwise, an attacker could modify the encrypted metadata 
            // and then the true user would not be able to access the file,
            // without knowing whether the file has been modified.
            
            byte[] salt = getField(metadata, Field.SALT, true);
            byte[] derivedKey = computeDerivedKey(password.getBytes(CHARACTER_SET), salt);
            
            // Compute the metadata digest and a compare to what is stored in metadata
            logger.fine("Computing metadata digest using derived key...");
            byte[] metadataDigest = getField(metadata, Field.METADATA_DIGEST, false);
            byte[] computedMetadataDigest = computeMetadataDigest(metadata, derivedKey);
            
            if (!Arrays.equals(metadataDigest, computedMetadataDigest)) {
                logger.warning("Metadata digest verification has failed.");
                result = false;
            } else {
                logger.fine("Metadata digest verification passed.");
            }
            
            // We need to decrypt the metadata so we can determine
            // how many file blocks we're dealing with. 
            byte[] plaintext = decryptMetadata(metadata, derivedKey);
            
            // Do the same thing for the file digest(s)
            byte[] length = getField(plaintext, Field.FILE_SIZE, false);
            int nPhysicalFiles = getNumPhysicalFiles(bytesToInteger(length));
            int digestStartIndex = fieldInfoMap.get(Field.FILE_DIGEST).get(FieldInfo.POSITION);
            int digestEndIndex   = digestStartIndex + fieldInfoMap.get(Field.FILE_DIGEST).get(FieldInfo.SIZE);
            
            for (int i = 0; i < nPhysicalFiles; i++) {
                String block = file_name + "/" + i;
                byte[] contents = read_from_file(new File(block));
                byte[] fileDigest = Arrays.copyOfRange(contents, digestStartIndex, digestEndIndex);
                byte[] computedFileDigest = computeFileDigest(contents, derivedKey);
                
                if (!Arrays.equals(fileDigest, computedFileDigest)) {
                    logger.warning("File digest verification has failed on " + block + ".");
                    result = false;
                    break;
                }
            }
            
            // NOW try to authenticate the user. According to the spec, 
            // an exception should be thrown on failure.
            
            if (!isCorrectPassword(plaintext, password)) {
                throw new PasswordIncorrectException();
            }
            
            return result;
            
        } catch (PasswordIncorrectException e) {
            logger.severe("Password incorrect.");
            throw e;
        } catch (Exception e) {
            logger.severe("Failed to find user for file " + file_name + ": " + e.getMessage());
            throw e;
        }
    }

    /**
     * Steps to consider... <p>
     *  - verify password <p>
     *  - truncate the content after the specified length <p>
     *  - re-pad, update metadata and HMAC <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {
        throw new PasswordIncorrectException();
    }
  
}
