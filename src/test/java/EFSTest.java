import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;

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
    
    private String getTemporaryFile() {
        return "test-" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(Calendar.getInstance().getTime()) + ".txt";
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
            file.delete();
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
        String filename = getTemporaryFile();
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
        String filename = getTemporaryFile();
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
        String filename = getTemporaryFile();
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
        String filename = getTemporaryFile();
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
        String filename = getTemporaryFile();
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
        String filename = getTemporaryFile();
        
        try {
            // Find user for non-existent file
            String result = efs.findUser("some-file-that-does-not-exist.txt");
            fail();
        } catch (Exception e) {
        }
    }
    
    public void testFindUserSucceeds() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        
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
    
    public void testFindUserThrowsOnNonExistentFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "IdoNotExist.txt";
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.findUser(filename);
            fail();
        } catch (FileNotFoundException e) {
        }
    }
    
    public void testLengthOnNewFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
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
        String filename = getTemporaryFile();
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
    
    public void testLengthThrowsOnNonExistentFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "IdoNotExist.txt";
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.length(filename, password);
            fail();
        } catch (FileNotFoundException e) {
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
    
    public void testCheckIntegrityThrowsOnNonExistentFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "IdoNotExist.txt";
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.check_integrity(filename, password);
            fail();
        } catch (FileNotFoundException e) {
        }
    }
    
    public void testCheckIntegrityThrowsOnIncorrectPassword() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
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
        String filename = getTemporaryFile();
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
        String filename = getTemporaryFile();
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
        String filename = getTemporaryFile();
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
    
    public void testWriteToFileBlockZeroOnBoundary() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.create(filename, username, password);
            assertEquals(0, efs.length(filename, password));

            // Start at zero
            
            // Length = 751
            String content = "The wave roared towards them with speed and violence they had not anticipated. They both turned to run but by that time it was too late. The wave crashed into their legs sweeping both of them off of their feet. They now found themselves in a washing machine of saltwater, getting tumbled and not know what was up or down. Both were scared not knowing how this was going to end, but it was by far the best time of the trip thus far.\n"
                    + "They decided to find the end of the rainbow. While they hoped they would find a pot of gold, neither of them truly believed that the mythical pot would actually be there. Nor did they believe they could actually find the end of the rainbow. Still, it seemed like a fun activity for the day and pictures of them chasing.";
            efs.write(filename, 0, content.getBytes(), password);

            assertEquals(true, new File(filename + "/0").exists());
            assertEquals(false, new File(filename + "/1").exists());
            assertEquals(751, efs.length(filename, password));


            // Length = 752 ==> Max size for file block 0
            content += ".";
            efs.write(filename, 0, content.getBytes(), password);

            assertEquals(true, new File(filename + "/0").exists());
            assertEquals(false, new File(filename + "/1").exists());
            assertEquals(752, efs.length(filename, password));
            
        }
        catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testWriteToFileBlockZeroAppendToEnd() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.create(filename, username, password);
            assertEquals(0, efs.length(filename, password));

            // Start at zero
            
            // Length = 432
            String content = "The wave roared towards them with speed and violence they had not anticipated. They both turned to run but by that time it was too late. The wave crashed into their legs sweeping both of them off of their feet. They now found themselves in a washing machine of saltwater, getting tumbled and not know what was up or down. Both were scared not knowing how this was going to end, but it was by far the best time of the trip thus far.\n";
            efs.write(filename, 0, content.getBytes(), password);

            assertEquals(true, new File(filename + "/0").exists());
            assertEquals(false, new File(filename + "/1").exists());
            assertEquals(432, efs.length(filename, password));

            // Length = 31 and starting at the end of the previous content
            content = "Here are some additional words.";
            efs.write(filename, 432, content.getBytes(), password);
            
            assertEquals(true, new File(filename + "/0").exists());
            assertEquals(false, new File(filename + "/1").exists());
            assertEquals(463, efs.length(filename, password));

        }
        catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testWriteFailsOnNonExistentFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "IdoNotExist.txt";
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.write(filename, 0, "some content".getBytes(), password);
            fail();
        } catch (FileNotFoundException e) {
        }
    }
    
    public void testWriteFailsOnIncorrectPassword() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
        
        efs.create(filename, username, password);
        password += "1"; // change the password
        
        try {
            efs.write(filename, 0, "some content".getBytes(), password);
            fail();
        } catch (PasswordIncorrectException e) {
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testWriteFailsWhenStartPositionGreaterThenCurrentLength() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
        
        efs.create(filename, username, password);
        
        try {
            efs.write(filename, 1, "some content".getBytes(), password);
            fail();
        } catch (Exception e) {
        } finally {
            deleteDirectory(filename);
        }
        
        efs.create(filename, username, password);
        password += "1"; // change the password
        
        try {
            efs.write(filename, 0, "some content".getBytes(), password);
            efs.write(filename, 12, "some content".getBytes(), password);
            fail();
        } catch (Exception e) {
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testWriteToFileBlockZeroAcrossBoundary() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.create(filename, username, password);
            assertEquals(0, efs.length(filename, password));

            // Start at zero
            
            // Length = 751
            String content = "The wave roared towards them with speed and violence they had not anticipated. They both turned to run but by that time it was too late. The wave crashed into their legs sweeping both of them off of their feet. They now found themselves in a washing machine of saltwater, getting tumbled and not know what was up or down. Both were scared not knowing how this was going to end, but it was by far the best time of the trip thus far.\n"
                    + "They decided to find the end of the rainbow. While they hoped they would find a pot of gold, neither of them truly believed that the mythical pot would actually be there. Nor did they believe they could actually find the end of the rainbow. Still, it seemed like a fun activity for the day and pictures of them chasing.";

            // Length = 771 ==> Max size for file block == 752
            content += ". Here is some more.";
            efs.write(filename, 0, content.getBytes(), password);

            assertEquals(true, new File(filename + "/0").exists());
            assertEquals(true, new File(filename + "/1").exists());
            assertEquals(771, efs.length(filename, password));
            
        }
        catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testWriteToFileBlockOneOnBoundary() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.create(filename, username, password);
            assertEquals(0, efs.length(filename, password));

            // Start at zero
            
            // Length = 1486
            String content = "The wave roared towards them with speed and violence they had not anticipated. They both turned to run but by that time it was too late. The wave crashed into their legs sweeping both of them off of their feet. They now found themselves in a washing machine of saltwater, getting tumbled and not know what was up or down. Both were scared not knowing how this was going to end, but it was by far the best time of the trip thus far.\n"
                    + "They decided to find the end of the rainbow. While they hoped they would find a pot of gold, neither of them truly believed that the mythical pot would actually be there. Nor did they believe they could actually find the end of the rainbow. Still, it seemed like a fun activity for the day and pictures of them chasing."
                    + "It went through such rapid contortions that the little bear was forced to change his hold on it so many times he became confused in the darkness, and could not, for the life of him, tell whether he held the sheep right side up, or upside down. But that point was decided for him a moment later by the animal itself, who, with a sudden twist, jabbed its horns so hard into his lowest ribs that he gave a grunt of anger and disgust.\n"
                    + "This is important to remember. Love isn't like pie. You don't need to divide it among all your friends and loved ones. No matter how much love you give, you can always give more. It doesn't run out, so don't try to hold back giving it as if it may one day run out. Give it freely and as much as you want.";
            efs.write(filename, 0, content.getBytes(), password);
            assertEquals(true, new File(filename + "/0").exists());
            assertEquals(true, new File(filename + "/1").exists());
            assertEquals(1486, efs.length(filename, password));
            
            // Length = 752 + 992 = 1744 ==> Max size for file block 0 and 1
            content += "The words hadn't flowed from his fingers for the past few weeks. He never imagined he'd find himself with writer's block, but here he sat with a blank screen in front of him. That blank screen taunting him day after day had started to play with his mind.....";
            efs.write(filename, 0, content.getBytes(), password);
            assertEquals(true, new File(filename + "/0").exists());
            assertEquals(true, new File(filename + "/1").exists());
            assertEquals(false, new File(filename + "/2").exists());
            assertEquals(1744, efs.length(filename, password));
            
        }
        catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testWriteToFileBlockOneAcrossBoundary() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.create(filename, username, password);
            assertEquals(0, efs.length(filename, password));

            // Start at zero
            
            // Length = 1739
            String content = "The wave roared towards them with speed and violence they had not anticipated. They both turned to run but by that time it was too late. The wave crashed into their legs sweeping both of them off of their feet. They now found themselves in a washing machine of saltwater, getting tumbled and not know what was up or down. Both were scared not knowing how this was going to end, but it was by far the best time of the trip thus far.\n"
                    + "They decided to find the end of the rainbow. While they hoped they would find a pot of gold, neither of them truly believed that the mythical pot would actually be there. Nor did they believe they could actually find the end of the rainbow. Still, it seemed like a fun activity for the day and pictures of them chasing."
                    + "It went through such rapid contortions that the little bear was forced to change his hold on it so many times he became confused in the darkness, and could not, for the life of him, tell whether he held the sheep right side up, or upside down. But that point was decided for him a moment later by the animal itself, who, with a sudden twist, jabbed its horns so hard into his lowest ribs that he gave a grunt of anger and disgust."
                    + "This is important to remember. Love isn't like pie. You don't need to divide it among all your friends and loved ones. No matter how much love you give, you can always give more. It doesn't run out, so don't try to hold back giving it as if it may one day run out. Give it freely and as much as you want."
                    + "The words hadn't flowed from his fingers for the past few weeks. He never imagined he'd find himself with writer's block, but here he sat with a blank screen in front of him. That blank screen taunting him day after day had started to play with his mind.";
            
            // Length = 1759
            content += ". Here is some more.";
            efs.write(filename, 0, content.getBytes(), password);
            
            assertEquals(true, new File(filename + "/0").exists());
            assertEquals(true, new File(filename + "/1").exists());
            assertEquals(true, new File(filename + "/2").exists());
            assertEquals(false, new File(filename + "/3").exists());
            assertEquals(1759, efs.length(filename, password));
            
        }
        catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testReadFailsOnNonExistentFile() throws Exception {
        EFS efs = new EFS(null);
        String filename = "IdoNotExist.txt";
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.read(filename, 0, 0, password);
            fail();
        } catch (FileNotFoundException e) {
        }
    }
    
    public void testReadFailsOnIncorrectPassword() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
        
        efs.create(filename, username, password);
        password += "1"; // change the password
        
        try {
            efs.read(filename, 0, 0, password);
            fail();
        } catch (PasswordIncorrectException e) {
        } finally {
            deleteDirectory(filename);
        }
    }

    public void testReadFailsWhenReadingMoreThanLength() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
        
        efs.create(filename, username, password);
        
        try {
            efs.read(filename, 0, 1, password);
            fail();
        } catch (Exception e) {
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testReadFileBlockZeroIsSuccess() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.create(filename, username, password);
            assertEquals(0, efs.length(filename, password));

            // Start at zero

            // Write some content
            String content = "The wave roared towards them with speed and violence they had not anticipated. They both turned to run but by that time it was too late. The wave crashed into their legs sweeping both of them off of their feet. They now found themselves in a washing machine of saltwater, getting tumbled and not know what was up or down. Both were scared not knowing how this was going to end, but it was by far the best time of the trip thus far.\n"
                    + "They decided to find the end of the rainbow. While they hoped they would find a pot of gold, neither of them truly believed that the mythical pot would actually be there. Nor did they believe they could actually find the end of the rainbow. Still, it seemed like a fun activity for the day and pictures of them chasing.";
            efs.write(filename, 0, content.getBytes(), password);
            
            // Try to read from 0 - 23
            String result = new String(efs.read(filename, 0, 23, password));
            assertEquals(0, result.compareTo("The wave roared towards"));
            
            // something1 - something2
            result = new String(efs.read(filename, 23, 20, password));
            assertEquals(0, result.compareTo(" them with speed and"));
            
        }
        catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testReadFromFileBlockZeroAcrossBoundary() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.create(filename, username, password);
            assertEquals(0, efs.length(filename, password));

            // Start at zero
            
            // Length = 751
            String content = "The wave roared towards them with speed and violence they had not anticipated. They both turned to run but by that time it was too late. The wave crashed into their legs sweeping both of them off of their feet. They now found themselves in a washing machine of saltwater, getting tumbled and not know what was up or down. Both were scared not knowing how this was going to end, but it was by far the best time of the trip thus far.\n"
                    + "They decided to find the end of the rainbow. While they hoped they would find a pot of gold, neither of them truly believed that the mythical pot would actually be there. Nor did they believe they could actually find the end of the rainbow. Still, it seemed like a fun activity for the day and pictures of them chasing.";

            // Length = 771 ==> Max size for file block == 752
            content += ". Here is some more.";
            efs.write(filename, 0, content.getBytes(), password);

            // Attempting to read across file blocks
            String result = new String(efs.read(filename, 726, 39, password));
            assertEquals(0, result.compareTo("pictures of them chasing.. Here is some"));
            
        }
        catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testReadFromFileBlockOneAcrossBoundary() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.create(filename, username, password);
            assertEquals(0, efs.length(filename, password));

            // Start at zero
            
            // Length = 1739 + 20 
            String content = "The wave roared towards them with speed and violence they had not anticipated. They both turned to run but by that time it was too late. The wave crashed into their legs sweeping both of them off of their feet. They now found themselves in a washing machine of saltwater, getting tumbled and not know what was up or down. Both were scared not knowing how this was going to end, but it was by far the best time of the trip thus far.\n"
                    + "They decided to find the end of the rainbow. While they hoped they would find a pot of gold, neither of them truly believed that the mythical pot would actually be there. Nor did they believe they could actually find the end of the rainbow. Still, it seemed like a fun activity for the day and pictures of them chasing."
                    + "It went through such rapid contortions that the little bear was forced to change his hold on it so many times he became confused in the darkness, and could not, for the life of him, tell whether he held the sheep right side up, or upside down. But that point was decided for him a moment later by the animal itself, who, with a sudden twist, jabbed its horns so hard into his lowest ribs that he gave a grunt of anger and disgust."
                    + "This is important to remember. Love isn't like pie. You don't need to divide it among all your friends and loved ones. No matter how much love you give, you can always give more. It doesn't run out, so don't try to hold back giving it as if it may one day run out. Give it freely and as much as you want."
                    + "The words hadn't flowed from his fingers for the past few weeks. He never imagined he'd find himself with writer's block, but here he sat with a blank screen in front of him. That blank screen taunting him day after day had started to play with his mind."
                    + ". Here is some more.";
            efs.write(filename, 0, content.getBytes(), password);
            
            // Attempting to read across file blocks
            String result = new String(efs.read(filename, 1725, 23, password));
            assertEquals(0, result.compareTo("with his mind.. Here is"));
        }
        catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testOverwriteInFileBlockOne() throws Exception {
        EFS efs = new EFS(null);
        String filename = getTemporaryFile();
        String username = "hxs200010";
        String password = "MyPassword";
                
        try {
            efs.create(filename, username, password);
            assertEquals(0, efs.length(filename, password));

            // Start at zero, write some content, read it all, overwrite something in the middle, read it all

            // Length = 136
            String content = "The wave roared towards them with speed and violence they had not anticipated. They both turned to run but by that time it was too late.";
            efs.write(filename, 0, content.getBytes(), password);
            assertEquals(136, efs.length(filename, password));
            
            byte[] result = efs.read(filename, 0, 136, password);
            assertEquals(0, new String(result).compareTo("The wave roared towards them with speed and violence they had not anticipated. They both turned to run but by that time it was too late."));
            
            // replacing "with speed and violence" with "here is some random stf"
            efs.write(filename, 29, "here is some random stf".getBytes(), password);
            assertEquals(136, efs.length(filename, password));

            result = efs.read(filename, 0, 136, password);
            System.out.println(new String(result));
            assertEquals(0, new String(result).compareTo("The wave roared towards them here is some random stf they had not anticipated. They both turned to run but by that time it was too late."));
            
        }
        catch (Exception e) {
            throw e;
        } finally {
            deleteDirectory(filename);
        }
    }
    
    public void testAllOpsWhenPasswordIncorrect() throws Exception {
        fail();
    }
    
    public void testAllOpsWhenFileDoesNotExist() throws Exception {
        fail();
    }
}
