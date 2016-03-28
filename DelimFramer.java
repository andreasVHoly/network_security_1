import java.io.*;

public class DelimFramer implements Framer{
    private InputStream in;
    private static final byte DELIMITER = "\n".getBytes();


    public DelimFramer(InputStream in){
        this.in = in;
    }


    public void frameMsg(byte[] message, OutputStream out) throws IOException{
        for(byte b : message){
            if (b == DELIMITER){
                throw new IOException("Message contains delim");
            }
        }

        out.write(message);
        out.write(DELIMITER);
        out.flush();
    }

    public byte[] nextMsg() throws IOException{
        ByteArrayOutputStream msgbuffer = new ByteArrayOutputStream();
        int nextByte;

        while((nextByte = in.read()) != DELIMITER){
            if (nextByte == -1){
                if (msgbuffer.size() == 0){
                    return null;
                }
                else{
                    throw new IOException ("Non empty message w/o delim");
                }
            }
            msgbuffer.write(nextByte);
        }
        return msgbuffer.toByteArray();
    }

}
