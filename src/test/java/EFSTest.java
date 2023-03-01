import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.commons.codec.binary.Hex;

/**
 * Unit test for simple App.
 */
public class EFSTest extends TestCase {
    
    private void deleteDirectory(String dirname) {
        File dir = new File(dirname);
        
        if (dir.exists()) {
            for (File file : dir.listFiles()) {
                file.delete();
            }
            dir.delete();
        }
    }
    
    public EFSTest( String testName ) {
        super( testName );
    }

    public static Test suite() {
        return new TestSuite( EFSTest.class );
    }

    public void tearDown() {
        File dir = new File(".");
        File[] files = dir.listFiles((d, name) -> name.startsWith("efs.log"));
        
        for (File file : files) {
            //file.delete();
        }
    }
    
    public void testGetNewPasswordSalt() {
        EFS efs = new EFS(null);
        
        String salt = efs.getNewPasswordSalt(16);
        assertEquals(salt.length(), 16);
        assertEquals(salt.getBytes(StandardCharsets.US_ASCII).length, 16);
    }
    
    public void testGetPasswordHash() throws Exception {
        EFS efs = new EFS(null);
        
        String password = "MyP@$$w0rD!23";
        String salt     = efs.getNewPasswordSalt(16);
        
        byte[] hash1 = efs.getPasswordHash(password, salt);
        byte[] hash2 = efs.getPasswordHash(password, salt);
        
        assertEquals(hash1.length, 32);
        assertEquals(hash2.length, 32);
        
        for (int i = 0; i < hash1.length; i++) {
            assertEquals(hash1[i], hash2[i]);
        }
        
        byte[] hash3 = efs.getPasswordHash(password+"1", salt);
        byte[] hash4 = efs.getPasswordHash(password, salt+"2");
        
        boolean matches = true;
        for (int i = 0; i < hash1.length; i++) {
            if (hash1[i] != hash3[i]) {
                matches = false;
                break;
            }
        }
        assertFalse(matches);
        
        matches = true;
        for (int i = 0; i < hash1.length; i++) {
            if (hash1[i] != hash4[i]) {
                matches = false;
                break;
            }
        }
        assertFalse(matches);
    }
    
    public void testCreateFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testFile.txt";
        String username = "hxs200010";
        String password = "MyPassword";

        try {
            efs.create(filename, username, password);
            
            // Check for the directory
            File file = new File(filename);
            assertTrue(file.exists());
            assertTrue(file.isDirectory());
            
            // Check for the physical file
            File phyFile = new File(file, "0");
            assertTrue(phyFile.exists());
            
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);            
        }
    }
    
    public void testCreateExistingFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testFile.txt";
        String username = "hxs200010";
        String password = "MyPassword";

        try {
            efs.create(filename, username, password);
            
            // Check for the directory
            File file = new File(filename);
            assertTrue(file.exists());
            assertTrue(file.isDirectory());
            
            // Check for the physical file
            File phyFile = new File(file, "0");
            assertTrue(phyFile.exists());
            
            // Try to create the file again
            efs.create(filename, username, password);
            
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);            
        }
    }
    
    public void testCreateFailsOnBadPath() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testFile.txt";
        String username = "hxs200010";
        String password = "MyPassword";
        
        try {
            // Try to create a file in /opt
            efs.create("/opt/test", username, password);
            fail();
            
        } catch(Exception e) {
        }
    }
    
    public void testCreateFailsOnTooLongUsername() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testFile.txt";
        String username = "";
        String password = "MyPassword";
        
        for (int i = 0; i < 128; i++) {
            username += "A";
        }

        try {
            efs.create(filename, username, password);
            
            // Check for the directory
            File file = new File(filename);
            assertTrue(file.exists());
            assertTrue(file.isDirectory());
            
            // Check for the physical file
            File phyFile = new File(file, "0");
            assertTrue(phyFile.exists());
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);            
        }
        
        // Add a letter over the maximum
        username += "A";
        try {
            efs.create(filename, username, password);
            fail();
        } catch(Exception e) {
        }
    }
    
    public void testCreateFailsOnTooLongPassword() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testFile.txt";
        String username = "hunter";
        String password = "";
        
        for (int i = 0; i < 128; i++) {
            password += "A";
        }

        try {
            efs.create(filename, username, password);
            
            // Check for the directory
            File file = new File(filename);
            assertTrue(file.exists());
            assertTrue(file.isDirectory());
            
            // Check for the physical file
            File phyFile = new File(file, "0");
            assertTrue(phyFile.exists());
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);            
        }
        
        // Add a letter over the maximum
        password += "A";
        try {
            efs.create(filename, username, password);
            fail();
        } catch(Exception e) {
        }
    }
    
    public void testFindUserFailsOnMissingFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testFindUser.txt";
        
        try {
            // Find user for non-existent file
            String result = efs.findUser("some-file-that-does-not-exist.txt");
            fail();
        } catch (Exception e) {
        }
    }
    
    public void testFindUserSucceeds() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testFindUser.txt";
        
        try {
            // Now try it on a real file
            String username = "hxs200010";
            String password = "MyP@$$W0Rd!23";
            efs.create(filename, username, password);
            
            String foundUser = efs.findUser(filename);
            assertTrue(foundUser.equals(username));
            
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testLengthOnMissingFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testLength.txt";
        String username = "hxs200010";
        String password = "MyP@$$W0Rd!23";
        
        try {
            // Try on non-existent file
            int length = efs.length(filename, password);
            fail();
            
        } catch (Exception e) {
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testLengthOnNewFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testLength.txt";
        String username = "hxs200010";
        String password = "MyP@$$W0Rd!23";
        
        try {
            efs.create(filename, username, password);
            int length = efs.length(filename, password);
            assertEquals(length, 0);
            
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testLengthThrowsPasswordIncorrectException() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testLength.txt";
        String username = "hxs200010";
        String password = "MyP@$$W0Rd!23";
        
        // First try with correct password
        efs.create(filename, username, password);
        int length = efs.length(filename, password);
        assertEquals(length, 0);
        
        try {
            // Now try with incorrect password
            length = efs.length(filename, password+"1");
            fail();
            
        } catch (PasswordIncorrectException e) {
            // passed
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testComputeHmac() throws Exception {
        EFS efs = new EFS(null);
        byte[] key = "key".getBytes(StandardCharsets.US_ASCII);
        byte[] message = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.US_ASCII);
        
        try {
            EFS.HashAlg alg = EFS.HashAlg.SHA256;
            byte[] hmacsha256 = efs.compute_HMAC(key, message, alg);
            assertTrue(Hex.encodeHexString(hmacsha256).equals("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));
            
            alg = EFS.HashAlg.SHA512;
            byte[] hmacsha512 = efs.compute_HMAC(key, message, alg);
            assertTrue(Hex.encodeHexString(hmacsha512).equals("b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"));
            
        } catch (Exception e) {
            throw e;
        }
    }
    
    public void testComputePBKDF2() throws Exception {
        EFS efs = new EFS(null);
        byte[] password = "HereIsMyKey123$%^".getBytes(StandardCharsets.US_ASCII);
        byte[] salt = "ThisIsMySalt!23$56&".getBytes(StandardCharsets.US_ASCII);
        int iter = 1000;
        int dkLen = 256;
        
        try {
            EFS.HashAlg alg = EFS.HashAlg.SHA256;
            byte[] result = efs.compute_PBKDF2_SHA256(password, salt, iter, dkLen);
            
            assertTrue(Hex.encodeHexString(result).equals("c0409d5527bf10c6d213deb435b6f566da7e4d3b223697ccfca8766eab25ac41"));
            
        } catch (Exception e) {
            throw e;
        }
    }
    
    /*public void testSample() throws Exception {
        Sample efs = new Sample(null);
        String filename = "testSample.txt";
        String username = "hunter";
        String password = "password";
        
        efs.create(filename, username, password);
        
        byte[] content = efs.read_from_file(new File("/tmp/test.txt"));
        efs.write(filename, 0, content, password);
        
        efs.write(filename, 0, "Here is my replacement".getBytes(), password);
        efs.write(filename, 0, "Here is my replacement".getBytes(), password);
    }*/
    
    public void testEncryptByteArraySuccessOnOneBlock() throws Exception {
        EFS efs = new EFS(null);
        
        byte[] plaintext = "He1l0 Th3r3 m@t3".getBytes(StandardCharsets.US_ASCII);
        byte[] key = efs.secureRandomNumber(16);
        byte[] ciphertext = efs.encryptByteArray(plaintext, key);
        byte[] decrypted = efs.decryptByteArray(ciphertext, key);
        
        assertTrue(Arrays.equals(decrypted, plaintext));
    }
    
    public void testEncryptByteArraySuccessOnTwoBlocks() throws Exception {
        EFS efs = new EFS(null);
        
        byte[] plaintext = "He1l0 Th3r3 m@t3, h0w @r3 Y0u Do".getBytes(StandardCharsets.US_ASCII);
        byte[] key = efs.secureRandomNumber(16);
        byte[] ciphertext = efs.encryptByteArray(plaintext, key);
        byte[] decrypted = efs.decryptByteArray(ciphertext, key);
        
        assertTrue(Arrays.equals(decrypted, plaintext));
    }
    
    public void testEncryptByteArraySuccessOnInBetweenBlocks() throws Exception {
        EFS efs = new EFS(null);
        
        byte[] plaintext = "He1l0 Th3r3 m@t3, h0w @r3 Y0u Do. By3!".getBytes(StandardCharsets.US_ASCII);
        byte[] key = efs.secureRandomNumber(16);
        byte[] ciphertext = efs.encryptByteArray(plaintext, key);
        byte[] decryptedPadded = efs.decryptByteArray(ciphertext, key);
        
        // Decrypted is padded up to some multiple of AES block size
        byte[] decrypted = Arrays.copyOfRange(decryptedPadded, 0, plaintext.length);
        
        assertTrue(Arrays.equals(decrypted, plaintext));
    }
    
    public void testGetNumPhysicalFiles() throws Exception {
        EFS efs = new EFS(null);
        
        assertEquals(1, efs.getNumPhysicalFiles(-1));
        assertEquals(1, efs.getNumPhysicalFiles(0));
        assertEquals(1, efs.getNumPhysicalFiles(1));
        assertEquals(1, efs.getNumPhysicalFiles(2));
        assertEquals(1, efs.getNumPhysicalFiles(751));
        assertEquals(1, efs.getNumPhysicalFiles(752)); // boundary of first file
        assertEquals(2, efs.getNumPhysicalFiles(753));
        assertEquals(2, efs.getNumPhysicalFiles(754));
        assertEquals(2, efs.getNumPhysicalFiles(1743));
        assertEquals(2, efs.getNumPhysicalFiles(1744)); // boundary of second file
        assertEquals(3, efs.getNumPhysicalFiles(1745));
        assertEquals(3, efs.getNumPhysicalFiles(1746));
        assertEquals(3, efs.getNumPhysicalFiles(2735));
        assertEquals(3, efs.getNumPhysicalFiles(2736));
        assertEquals(4, efs.getNumPhysicalFiles(2737));
        assertEquals(4, efs.getNumPhysicalFiles(2738));
    }
    
    public void testCheckIntegrityThrowsOnMissingFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testCheckIntegrity.txt";
        String username = "hxs200010";
        String password = "MyPassword";

        try {
            efs.check_integrity(filename, password);
            fail();
        } catch (Exception e) {
        }
    }
    
    public void testCheckIntegrityThrowsOnIncorrectPassword() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testCheckIntegrity.txt";
        String username = "hxs200010";
        String password = "MyPassword";
        
        efs.create(filename, username, password);
        password += "1"; // change the password
        
        try {
            efs.check_integrity(filename, password);
            fail();
        } catch (PasswordIncorrectException e) {
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testCheckIntegrityPassesOnNewFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testCheckIntegrity.txt";
        String username = "hxs200010";
        String password = "MyPassword";
        
        efs.create(filename, username, password);
        
        try {
            assertEquals(true, efs.check_integrity(filename, password));
        } catch(Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testCheckIntegrityReturnsFalseWhenModifyUsername() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testCheckIntegrity.txt";
        String metadataFile = filename + "/0";
        String username = "hxs200010";
        String password = "MyPassword";
        
        efs.create(filename, username, password);
        assertEquals(true, efs.check_integrity(filename, password));
        
        // Now modify some bytes in the metadata,
        // although we need to make sure and modify something other than the password hash
        byte[] contents = efs.read_from_file(new File(metadataFile));
        
        // Changing hxs200010 to hxs202010
        contents[5] = (byte) 0x02;
        efs.save_to_file(contents, new File(metadataFile));
        
        try {
            assertEquals(false, efs.check_integrity(filename, password));
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testCheckIntegrityReturnsFalseWhenModifyFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testCheckIntegrity.txt";
        String metadataFile = filename + "/0";
        String username = "hxs200010";
        String password = "MyPassword";
        
        efs.create(filename, username, password);
        assertEquals(true, efs.check_integrity(filename, password));
        
        // Now modify some bytes in the metadata,
        // although we need to make sure and modify something other than the password hash
        byte[] contents = efs.read_from_file(new File(metadataFile));
        
        // Changing the initial file contents 
        contents[245] = (byte) 0xa5;
        efs.save_to_file(contents, new File(metadataFile));
        
        try {
            assertEquals(false, efs.check_integrity(filename, password));
        } catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testCheckIntegrityForMultipleFiles() throws Exception {
        fail();
    }
    
    public void testWriteToFileBlockZero() throws Exception {
        EFS efs = new EFS(null);
        String filename = "testWriteToFileBlockZero.txt";
        String username = "hxs200010";
        String password = "MyPassword";
                
        
        efs.create(filename, username, password);
        
        byte[] content = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes();
        efs.write(filename, 0, content, password);
       
        
        
    }
}
