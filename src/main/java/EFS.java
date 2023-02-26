import java.io.File;
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
     *  This enum aligns with the format of the metadata. 
     */
    public static enum MetadataField {
        USERNAME,
        SALT,
        PASSWORD_HASH,
        FEK,
        FILE_SIZE,
        METADATA_DIGEST,
        FILE_DIGEST
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
    private int AES_BLOCK_SIZE = 128;
    private int N_PBDFK2_ITERATIONS = 1000;
    private int DERIVED_KEY_LENGTH = 256;    // setting to same output length of SHA

    // This will be used for faster access to metadata field positions.
    private Map<MetadataField, Integer> metadataFieldPositionMap = new HashMap<MetadataField, Integer>();
    
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
    public byte[] getMetadataField(byte[] metadata, MetadataField field, boolean isEncrypted) throws Exception {
        
        int startIndex = metadataFieldPositionMap.get(field);
        
        if (field == MetadataField.USERNAME) {
            return Arrays.copyOfRange(metadata, startIndex, startIndex + N_USERNAME_BYTES);
            
        } else if (field == MetadataField.SALT) {
            return Arrays.copyOfRange(metadata, startIndex, startIndex + N_SALT_BYTES);
            
        } else if (field == MetadataField.PASSWORD_HASH) {
            logger.warning("Retrieving password hash from encrypted data.");
            return Arrays.copyOfRange(metadata, startIndex, startIndex + getHashOutputSize(PASSWORD_HASH_ALG));
            
        } else if (field == MetadataField.FEK) {
            logger.warning("Retrieving FEK from encrypted data.");
            return Arrays.copyOfRange(metadata, startIndex, startIndex + N_FEK_BYTES);
            
        } else if (field == MetadataField.FILE_SIZE) {
            logger.warning("Retrieving file size from encrypted data.");
            return Arrays.copyOfRange(metadata, startIndex, startIndex + N_LENGTH_BYTES);
            
        } 
        
        if (!isEncrypted) {
            
            if (field == MetadataField.METADATA_DIGEST) {
                return Arrays.copyOfRange(metadata, startIndex, startIndex + getHashOutputSize(METADATA_DIGEST_ALG));
                
            } else if (field == MetadataField.FILE_DIGEST) {
                return Arrays.copyOfRange(metadata, startIndex, startIndex + getHashOutputSize(FILE_DIGEST_ALG));
            }
            
        } else {
            // We must account for the extra padding of the secret data...
            startIndex = metadataFieldPositionMap.get(MetadataField.PASSWORD_HASH) + getSecretMetadataSize(true);
            
            if (field == MetadataField.METADATA_DIGEST) {
                return Arrays.copyOfRange(metadata, startIndex, startIndex + getHashOutputSize(METADATA_DIGEST_ALG));
                
            } else if (field == MetadataField.FILE_DIGEST) {
                return Arrays.copyOfRange(metadata, startIndex, startIndex + getHashOutputSize(FILE_DIGEST_ALG));
            }
        }
        
        logger.warning("Could not retrieve metadata field " + field + " from metadata.");
        return null; // we should never reach this
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
        return N_USERNAME_BYTES + N_SALT_BYTES + getSecretMetadataSize(isEncrypted) + getHashOutputSize(METADATA_DIGEST_ALG) + getHashOutputSize(FILE_DIGEST_ALG);
    }
    
    /**
     * Fetch file metadata.
     * @param filename
     * @return Metadata as byte array.
     * @throws Exception
     */
    public byte[] getFileMetadata(String filename) throws Exception {
        dir = new File(filename);
        File file = new File(dir, "0");
        
        if (file.exists()) {
            byte[] contents = read_from_file(file);
            return Arrays.copyOfRange(contents, 0, getMetadataSize(true));
        } else {
            return null;
        }
    }
    
    /**
     * Decrypt the file metadata.
     * @param metadata The file's metadata
     * @param password The password
     * @return Full, plaintext metadata, including header, secrets, and digests.
     */
    public byte[] decryptMetadata(byte[] metadata, String password) throws Exception {
        logger.info("ENTRY decryptMetadata");

        int nCiphertextSecretBytes = getSecretMetadataSize(true);
        int nPlaintextSecretBytes  = getSecretMetadataSize(false);
        int nTotalPlaintextBytes   = getMetadataSize(false);
        
        logger.fine("Fetching salt...");
        byte[] salt = getMetadataField(metadata, MetadataField.SALT, true);
        
        logger.info("Deriving key from password...");
        byte[] derivedkey = compute_PBKDF2(password.getBytes(CHARACTER_SET), salt, N_PBDFK2_ITERATIONS, DERIVED_KEY_LENGTH, PBKDF2_HASH_ALG);
        
        // Only a portion of the metadata is encrypted...
        logger.fine("Decrypting secret metadata section...");
        int startIndex = metadataFieldPositionMap.get(MetadataField.PASSWORD_HASH);
        int endIndex = startIndex + nCiphertextSecretBytes;
        
        byte[] encryptedMetadata = Arrays.copyOfRange(metadata, startIndex, endIndex);
        byte[] secrets = decryptByteArray(encryptedMetadata, derivedkey);
        
        // Copy to new array.
        byte[] result = new byte[nTotalPlaintextBytes];
        System.arraycopy(metadata, 0, result, 0,          startIndex);            // copy plaintext header
        System.arraycopy(secrets,  0, result, startIndex, nPlaintextSecretBytes); // copy plaintext secrets, ignoring the extra padding
        System.arraycopy(metadata, 0, result, startIndex + nPlaintextSecretBytes, metadata.length - endIndex); // copy the remaining contents of the metadata
        
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
        byte[] salt = getMetadataField(metadata, MetadataField.SALT, true);
        byte[] passwordHash = getPasswordHash(password, new String(salt, CHARACTER_SET));
        byte[] storedPasswordHash = getMetadataField(metadata, MetadataField.PASSWORD_HASH, isEncrypted);
        
        if (Arrays.equals(passwordHash, storedPasswordHash)) {
            return true; 
        } else {
            return false;
        }
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
    
    // END Utility functions
    //////////////////////////////////////////////////////////////////////
    
    //////////////////////////////////////////////////////////////////////
    // BEGIN Encryption/decryption/HMAC/Key derivation algorithms
    
    /**
     * Encrypts plaintext byte array using CTR mode.
     * @param plaintext
     * @param key
     * @return Ciphertext byte array.
     */
    public byte[] encryptByteArray(byte[] plaintext, byte[] key) throws Exception {
        logger.fine("ENTRY encryptByteArray plaintext.length = " + plaintext.length + " bytes, key.length = " + key.length + " bytes.");
        
        if (plaintext.length > AES_BLOCK_SIZE) {
            logger.fine("Encrypting via CTR mode...");
            
            int nblocks = (int)Math.ceil((double)plaintext.length / AES_BLOCK_SIZE);
            byte[] ciphertext = new byte[nblocks * AES_BLOCK_SIZE];
            int currentPosition = 0; 
            int nextPosition = AES_BLOCK_SIZE;
            
            for (int i = 0; i < nblocks; i++) {
                byte[] nextKey = integerToBytes(bytesToInteger(key) + (int)i);
                byte[] ciphertextBlock = encript_AES(Arrays.copyOfRange(plaintext, currentPosition, nextPosition), nextKey);
                
                System.arraycopy(ciphertextBlock, 0, ciphertext, currentPosition, AES_BLOCK_SIZE);
                
                currentPosition = nextPosition;
                nextPosition += AES_BLOCK_SIZE;
            }
            
            return ciphertext;
            
        } else {
            logger.fine("Encrypting single block...");
            return encript_AES(plaintext, key);
        }
    }
    
    /**
     * Decrypts ciphertext byte array using CTR mode.
     * @param ciphertext
     * @param key
     * @return
     */
    public byte[] decryptByteArray(byte[] ciphertext, byte[] key) throws Exception {
        logger.fine("ENTRY decryptByteArray ciphertext.length = " + ciphertext.length + " bytes, key.length = " + key.length + " bytes.");
        
        if (ciphertext.length > AES_BLOCK_SIZE) {
            logger.fine("Decrypting via CTR mode...");

            int nblocks = (int)Math.ceil((double)ciphertext.length / AES_BLOCK_SIZE);
            byte[] plaintext = new byte[nblocks * AES_BLOCK_SIZE];
            int currentPosition = 0; 
            int nextPosition = AES_BLOCK_SIZE;
            
            for (int i = 0; i < nblocks; i++) {
                byte[] nextKey = integerToBytes(bytesToInteger(key) + (int)i);
                byte[] plaintextBlock = decript_AES(Arrays.copyOfRange(ciphertext, currentPosition, nextPosition), nextKey);
                
                System.arraycopy(plaintextBlock, 0, plaintext, currentPosition, AES_BLOCK_SIZE);
                
                currentPosition = nextPosition;
                nextPosition += AES_BLOCK_SIZE;
            }
            
            return plaintext;
            
        } else {
            logger.fine("Decrypting single block...");
            return decript_AES(ciphertext, key);
        }
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
        int outputSize = getHashOutputSize(hashAlg);
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
        logger.fine("ENTRY compute_PBKDF2 " + niterations + " " + dkLen + " " + hashAlg);
        
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
            metadataFieldPositionMap.put(MetadataField.USERNAME, 0);
            metadataFieldPositionMap.put(MetadataField.SALT,          metadataFieldPositionMap.get(MetadataField.USERNAME) + N_USERNAME_BYTES);
            metadataFieldPositionMap.put(MetadataField.PASSWORD_HASH, metadataFieldPositionMap.get(MetadataField.SALT) + N_SALT_BYTES);
            metadataFieldPositionMap.put(MetadataField.FEK,           metadataFieldPositionMap.get(MetadataField.PASSWORD_HASH) + getHashOutputSize(PASSWORD_HASH_ALG));
            metadataFieldPositionMap.put(MetadataField.FILE_SIZE,     metadataFieldPositionMap.get(MetadataField.FEK) + N_FEK_BYTES);
            metadataFieldPositionMap.put(MetadataField.METADATA_DIGEST, metadataFieldPositionMap.get(MetadataField.FILE_SIZE) + N_LENGTH_BYTES);
            metadataFieldPositionMap.put(MetadataField.FILE_DIGEST,     metadataFieldPositionMap.get(MetadataField.METADATA_DIGEST) + getHashOutputSize(METADATA_DIGEST_ALG));
            
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
        logger.fine("ENTRY create " + file_name + " " + user_name);
        
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
            
            //################
            // Begin header section...
            
            if (user_name.length() > N_USERNAME_BYTES) {
                String msg = "Username longer than " + N_USERNAME_BYTES + " bytes.";
                logger.severe(msg);
                throw new Exception(msg);
            }

            byte[] header = new byte[ N_USERNAME_BYTES + N_SALT_BYTES ];
            logger.fine("Username = " + N_USERNAME_BYTES + " bytes, salt = " + N_SALT_BYTES + " bytes, header size = " + header.length + " bytes.");
            
            // Add the username
            System.arraycopy(user_name.getBytes(CHARACTER_SET), 0, header, 0, user_name.length());
            
            // Add the salt
            logger.fine("Generating new salt...");
            String salt = getNewPasswordSalt(N_SALT_BYTES);
            logger.fine("Salt = " + salt.length() + " bytes.");
            System.arraycopy(salt.getBytes(CHARACTER_SET), 0, header, N_USERNAME_BYTES, N_SALT_BYTES);
            
            //################
            // Begin secret section...
            
            int nEncryptedBytes = getSecretMetadataSize(true);
            
            logger.fine("Hashing password...");
            byte[] passwordHash = getPasswordHash(password, salt);
            logger.fine("Password hash = " + passwordHash.length + " bytes.");
            
            logger.fine("Generating FEK for this new file...");
            byte[] fek = secureRandomNumber(N_FEK_BYTES);
            logger.fine("FEK = " + fek.length + " bytes.");
            
            byte[] fileLength = integerToBytes(0);  // We are not storing anything yet
            logger.fine("File length = " + fileLength.length + " bytes.");
            
            // Store secret data into temp array so we can encrypt it
            byte[] secretData = new byte[nEncryptedBytes];
            logger.fine("Secret metadata = " + secretData.length + " bytes.");
            
            System.arraycopy(passwordHash,  0, secretData, 0,                                passwordHash.length);
            System.arraycopy(fek,           0, secretData, passwordHash.length,              fek.length);
            System.arraycopy(fileLength,    0, secretData, passwordHash.length + fek.length, fileLength.length);

            logger.fine("Deriving encryption key from password...");
            byte[] derivedKey = compute_PBKDF2(password.getBytes(CHARACTER_SET), salt.getBytes(CHARACTER_SET), N_PBDFK2_ITERATIONS, DERIVED_KEY_LENGTH, PBKDF2_HASH_ALG);
            logger.fine("Derived key = " + derivedKey.length + " bytes.");
            
            logger.fine("Encrypting secret metadata...");
            byte[] encryptedMetadata = encryptByteArray(secretData, derivedKey);
            logger.fine("Secret metadata = " + encryptedMetadata.length + " bytes.");
            
            //################
            // Begin digest section...
            
            // Metadata digest. We will use the derived key.
            logger.fine("Computing metadata digest...");
            byte[] metadata = new byte[header.length + encryptedMetadata.length];
            System.arraycopy(header, 0, metadata, 0, header.length);
            System.arraycopy(encryptedMetadata, 0, metadata, header.length, encryptedMetadata.length);
            
            byte[] metadataDigest = compute_HMAC(derivedKey, metadata, METADATA_DIGEST_ALG);
            
            // Sanity check...
            int metadataSize = metadata.length + getHashOutputSize(METADATA_DIGEST_ALG) + getHashOutputSize(FILE_DIGEST_ALG);
            if (metadataSize > Config.BLOCK_SIZE) {
                throw new Exception("Metadata section size (" + metadataSize + ") exceeds physical file size limit (" + Config.BLOCK_SIZE +")");
            }
            
            // We will write a full block, initialize it with data we know
            byte[] toWrite = new byte[Config.BLOCK_SIZE];
            System.arraycopy(header,            0, toWrite, 0,                                        header.length);
            System.arraycopy(encryptedMetadata, 0, toWrite, header.length,                            encryptedMetadata.length);
            System.arraycopy(metadataDigest,    0, toWrite, header.length + encryptedMetadata.length, metadataDigest.length);
            
            // File digest. We will use the derived key.
            logger.fine("Computing file digest...");
            byte[] fileDigest = compute_HMAC(derivedKey, metadata, METADATA_DIGEST_ALG);
            
            System.arraycopy(fileDigest,        0, toWrite, header.length + encryptedMetadata.length + metadataDigest.length, fileDigest.length);
            
            
            // Fill empty file up to Config.BLOCK_SIZE
            logger.fine("Metadata digest = " + metadataDigest.length + " bytes, file digest = " + fileDigest.length + " bytes, metadata size = " + metadataSize + " bytes.");
            
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
        logger.fine("ENTRY findUser " + file_name);
        
        try {
        
            logger.fine("Fetching file metadata...");
            byte[] metadata = getFileMetadata(file_name);
            if (metadata == null) {
                String msg = "Failed to retrieve metadata for file " + file_name + ".";
                logger.severe(msg);
                throw new Exception(msg);
            }
        
            byte[] usernameBytes = getMetadataField(metadata, MetadataField.USERNAME, true);
            
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
     * Steps to consider...:<p>
     *  - get password, salt then AES key <p>     
     *  - decrypt password hash out of encrypted secret data <p>
     *  - check the equality of the two password hash values <p>
     *  - decrypt file length out of encrypted secret data
     */
    @Override
    public int length(String file_name, String password) throws Exception {
        logger.fine("ENTRY length " + file_name);
        
        try {
            logger.fine("Fetching file metadata...");
            byte[] metadata = getFileMetadata(file_name);
            
            if (metadata == null) {
                String msg = "Failed to retrieve metadata for file " + file_name + ".";
                logger.severe(msg);
                throw new Exception(msg);
            }
                        
            logger.fine("Decrypting metadata...");
            byte[] plaintext = decryptMetadata(metadata, password);
            
            logger.info("Checking password...");
            if (!isCorrectPassword(plaintext, password)) {
                throw new PasswordIncorrectException();
            }
            logger.fine("Password is correct.");
            
            logger.info("Getting length of file...");
            byte[] lengthBytes = getMetadataField(plaintext, MetadataField.FILE_SIZE, false);
            int length = bytesToInteger(lengthBytes);
            
            logger.fine("Length of file = " + length + " bytes.");
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
        throw new PasswordIncorrectException();
    }

    
    /**
     * Write new content to file. Note, this will overwrite data from the
     * starting_position to the starting position + content.length.
     * @param file_name
     * @parma starting_position 
     * @param content
     * @param password
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        logger.fine("ENTRY write " + file_name + " " + starting_position + " " + content.length);
        
        try {
            logger.fine("Fetching file metadata...");
            byte[] metadata = getFileMetadata(file_name);
            if (metadata == null) {
                String msg = "Failed to retrieve metadata for file " + file_name + ".";
                logger.severe(msg);
                throw new Exception(msg);
            }

            logger.fine("Decrypting metadata...");
            byte[] plaintextMetadata = decryptMetadata(metadata, password);

            logger.info("Checking password...");
            if (!isCorrectPassword(plaintextMetadata, password)) {
                throw new PasswordIncorrectException();
            }
            logger.fine("Password is correct.");

            logger.fine("Getting file length of " + file_name + "...");
            int fileLength = 0;
            fileLength = bytesToInteger(getMetadataField(plaintextMetadata, MetadataField.FILE_SIZE, false));
            logger.fine("File length = " + fileLength);

            if (starting_position > fileLength) {
                throw new Exception("Starting position for write (" + starting_position
                        + ") is greater than the current file length (" + fileLength + ").");
            }
            
            logger.fine("Getting FEK...");
            byte[] fek = getMetadataField(plaintextMetadata, MetadataField.FEK, false);
            
            

            logger.info("Writing " + content.length + " bytes to file " + file_name + "...");
            
            String strContent = byteArray2String(content);
            File root = new File(file_name);

            // We will need to grab the contents before and after this block of new content.
            int contentLength = strContent.length();
            
            // The file contents start right after the metadata.
            int startFileBlock = (metadata.length + starting_position) / Config.BLOCK_SIZE; 
            int endFileBlock   = (metadata.length + starting_position + contentLength) / Config.BLOCK_SIZE;
            
            // We only want to decrypt the portions that we are overwriting
            int startAesBlock = starting_position / AES_BLOCK_SIZE;
            int endAesBlock   = (starting_position + contentLength) / AES_BLOCK_SIZE;
            int nAesBlocksCurrently = fileLength / AES_BLOCK_SIZE;

            byte[] toOverwritePlaintext = 

            for (int i = startFileBlock; i <= endFileBlock; i++) {

                // Determine the start and end points
                int sp = i * Config.BLOCK_SIZE - starting_position;
                int ep = (i + 1) * Config.BLOCK_SIZE - starting_position;
                
                String encryptedPrefix = "";  // the data before the starting point 
                String encryptedPostfix = ""; // the data after the end point

                // Get the prefix
                // If we're on the first file block...
                if (i == startFileBlock) {
                    
                    // We only need to grab a prefix if we are in the middle of some file block
                    if (starting_position != startFileBlock * Config.BLOCK_SIZE) {

                        // Get all of the file block contents
                        encryptedPrefix = byteArray2String(read_from_file(new File(root, Integer.toString(i))));
                        
                        // Get the data before the starting point
                        encryptedPrefix = encryptedPrefix.substring(0, starting_position - metadata.length - startFileBlock * Config.BLOCK_SIZE);
                        
                        // ?
                        sp = Math.max(sp, 0);
                    }
                }

                // If we're on the last block...
                if (i == endFileBlock) {
                    
                    File end = new File(root, Integer.toString(i));
                    if (end.exists()) {

                        encryptedPostfix = byteArray2String(read_from_file(new File(root, Integer.toString(i))));

                        if (encryptedPostfix.length() > starting_position + contentLength - endFileBlock * Config.BLOCK_SIZE) {
                            encryptedPostfix = encryptedPostfix.substring(starting_position + contentLength - endFileBlock * Config.BLOCK_SIZE);
                        }
                        else {
                            encryptedPostfix = "";
                        }
                    }
                    ep = Math.min(ep, contentLength);
                }

                String toWrite = encryptedPrefix + strContent.substring(sp, ep) + encryptedPostfix;

                while (toWrite.length() < Config.BLOCK_SIZE) {
                    toWrite += '\0';
                }

                save_to_file(toWrite.getBytes(), new File(root, Integer.toString(i)));
            }
        }
        catch (Exception e) {
            logger.severe("Failed to write content to file " + file_name + ".");
            throw e;
        }

        // update meta data

        if (content.length + starting_position > length(file_name, password)) {
            File root = new File("");
            String s = byteArray2String(read_from_file(new File(root, "0")));
            String[] strs = s.split("\n");
            strs[0] = Integer.toString(content.length + starting_position);
            String toWrite = "";
            for (String t : strs) {
                toWrite += t + "\n";
            }
            while (toWrite.length() < Config.BLOCK_SIZE) {
                toWrite += '\0';
            }
            save_to_file(toWrite.getBytes(), new File(root, "0"));

        }
    }

    /**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        throw new Exception();
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
