import java.nio.charset.StandardCharsets;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class EFSTest extends TestCase {
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public EFSTest( String testName ) {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite( EFSTest.class );
    }

    public void testGetNewPasswordSalt() {
        EFS efs = new EFS(null);
        
        String salt = efs.getNewPasswordSalt();
        assertEquals(salt.length(), 16);
        assertEquals(salt.getBytes(StandardCharsets.US_ASCII).length, 16);
    }
    
    public void testGetPaddedUsername() {
        EFS efs = new EFS(null);
        String username = "";
        
        for (int i = 0; i < 128; i++) {
            username += "a";
        }
        
        try {
            efs.getPaddedUsername(username);
            username += "a";
            efs.getPaddedUsername(username);
            fail();
        } catch(Exception e) {
            System.out.println("Caught exception: " + e.getMessage());
        }
        
        username = "hxs200010";
        try {
            username = efs.getPaddedUsername(username);
        } catch(Exception e) {
            fail();
        }
        
        assertEquals(username.length(), 128);
    }
    
    public void testGetPasswordHash() {
        EFS efs = new EFS(null);
        
        String password = "MyP@$$w0rD!23";
        String salt     = efs.getNewPasswordSalt();
        byte[] hash1 = null;
        byte[] hash2 = null;
        
        try {
            hash1 = efs.getPasswordHash(password, salt);
        } catch (Exception e) {
            fail();
        }
        try {
            hash2 = efs.getPasswordHash(password, salt);
        } catch (Exception e) {
            fail();
        }
        
        for (int i = 0; i < hash1.length; i++) {
            assertEquals(hash1[i], hash2[i]);
        }
    }
    
    public void testCreate() {
        EFS efs = new EFS(null);
        
        try {
            efs.create("testFile.txt", "hxs200010", "MyPassword");
        } catch (Exception e) {
            System.out.println(e.getMessage());
            fail();
        }
    }
}
