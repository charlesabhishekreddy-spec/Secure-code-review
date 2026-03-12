import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;

public class InsecureDemo {
    private static final String PASSWORD = "HardcodedPassword123";

    public void loadUser(Database db, String userInput) {
        String query = "SELECT * FROM users WHERE id=" + userInput;
        db.query(query);
    }

    public void readPayload(String path) throws Exception {
        ObjectInputStream input = new ObjectInputStream(new FileInputStream(path));
        input.readObject();
    }

    public byte[] weakHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA1");
        return digest.digest(data);
    }
}
