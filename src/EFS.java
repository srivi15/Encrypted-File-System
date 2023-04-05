
/**
 * @author Srividhya Ranganathan
 * @netid sxr200136
 * @email sxr200136@utdallas.edu
 */

import java.io.File;
import java.io.FileNotFoundException;
import java.lang.reflect.Array;
import java.net.StandardSocketOptions;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Arrays;

public class EFS extends Utility{

    public EFS(Editor e)
    {
        super(e);
        set_username_password();
    }

    // method to calculate HMAC
    public byte[] calculateHMAC(byte[] key, byte[] message) throws Exception{
        try {
            int blockLen = 64; // for one file block, 64 message blocks.

            byte[] opad = new byte[blockLen];
            byte[] ipad = new byte[blockLen];

            if (key.length > blockLen) {
                key = hash_SHA256(key);
            }

            // padding the key
            for (int i = 0; i < key.length; i++) {
                opad[i] = (byte) (0x5c ^ key[i]);
                ipad[i] = (byte) (0x36 ^ key[i]);
            }

            for (int i = key.length; i < blockLen; i++) {
                opad[i] = 0x5c;
                ipad[i] = 0x36;
            }

            // first round of hashing
            byte[] hash1Data = new byte[message.length + blockLen];
            System.arraycopy(ipad, 0, hash1Data, 0, blockLen);
            System.arraycopy(message, 0, hash1Data, blockLen, message.length);
            byte[] Hash1 = hash_SHA256(hash1Data);

            // final hashing that gives HMAC output
            byte[] Hash2Data = new byte[Hash1.length + blockLen];
            System.arraycopy(opad, 0, Hash2Data, 0, blockLen);
            System.arraycopy(Hash1, 0, Hash2Data, blockLen, Hash1.length);
            byte[] HMAC = hash_SHA256(Hash2Data);

            return HMAC;

        }
        catch(Exception e){
            throw new RuntimeException("Unsolved Exception", e);
        }
    }
    /**
     * Steps to consider... <p>
     *  - add padded username and password salt to header <p>
     *  - add password hash and file length to secret data <p>
     *  - AES encrypt padded secret data <p>
     *  - add header and encrypted secret data to metadata <p>
     *  - compute HMAC for integrity check of metadata <p>
     *  - add metadata and HMAC to metadata file block <p>
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        dir = new File(file_name);

        dir.mkdirs();
        File meta = new File(dir, "0");
        String toWrite = "";

        String length = Base64.getEncoder().encodeToString("0".getBytes("UTF-8"));

        toWrite = length + "\n";  //length of the file line 0
        toWrite += user_name + "\n";   //add username  line 1



        byte[] salt=secureRandomNumber(16);
        String salt_str = Base64.getEncoder().encodeToString(salt);

        // line 2
        toWrite+=salt_str + "\n";
        //String k=new String(salt);

        String str1= salt_str+password;
        // System.out.print("pass_salt1"+str1);
        byte[] temp= hash_SHA256(str1.getBytes("UTF-8"));

//        System.out.println("Hash length : " + temp.length);

        // line 3
        String hashed_pwd = Base64.getEncoder().encodeToString(temp);
        toWrite+=hashed_pwd + "\n";
        // toWrite+="\n";

        byte[] iv = secureRandomNumber(16);
        byte[] secretKey1 = secureRandomNumber(16);
        String iv_str = Base64.getEncoder().encodeToString(iv);
        String secretKey1_str = Base64.getEncoder().encodeToString(secretKey1);

        toWrite += iv_str + "\n"; // line 4 for IV
        toWrite += secretKey1_str + "\n"; // line 5 for encryption key

//        System.out.println("\nsecretKey in create: "+secretKey1);
//        System.out.println("\niv in create: "+iv);

//        System.out.println("\n\nsecretKey in create: "+ new String(secretKey1));
//        System.out.println("\niv in create: "+ new String(iv));

        // System.out.println("Final Metadata to Write : " + toWrite);
        while (toWrite.getBytes("UTF-8").length < Config.BLOCK_SIZE) {
            toWrite += '\0';
        }
        byte[] metaHMAC = calculateHMAC(secretKey1, toWrite.getBytes("UTF-8"));
        String metaHMACStr = Base64.getEncoder().encodeToString(metaHMAC);
        createHMACFile(metaHMAC, file_name);

        save_to_file(toWrite.getBytes("UTF-8"), meta);
        //return;

    }

    public void createHMACFile(byte[] hmac, String file_name) throws Exception{
        File root = new File(file_name);
        //root.mkdirs();
        File f1 = new File(root, "hmacFile");
        String toWrite = "";
        String hmacString = Base64.getEncoder().encodeToString(hmac);
        toWrite += hmacString;
        toWrite += "\n";
        save_to_file(toWrite.getBytes("UTF-8"), f1);
    }

    public void updateHMAC(String hmac, int i, String file_name) throws Exception{
        File root = new File(file_name);
        File f2 = new File(root, "hmacFile");

        if (!f2.exists()) {
            throw new FileNotFoundException("hmacFile is not found");
        }

        String s = new String(read_from_file(f2), "UTF-8");

        String[] content = s.split("\n");
        int contentLength = content.length;

        while (i >= contentLength) {
            content = Arrays.copyOf(content, contentLength + 1);
            content[contentLength] = "";
            contentLength++;
        }

        if(i>=contentLength){
            s+=hmac;
            s+="\n";
            //System.out.println("HMAC in update file: " + s);
        }
        else {
            content[i] = hmac;
            s = String.join("\n", content);
            //System.out.println("HMAC in update file: " + content[i]);
        }
        //System.out.println("content length in hmac file: "+content.length);
        //System.out.println("block number: "+(i));
        //if(i<=contentLength)
        //content[i] = hmac;
        //s = String.join("\n", content);
        //s += hmac;
        //s += "\n";

        save_to_file(s.getBytes("UTF-8"), f2);
    }

    public void deleteHMAC(int i, String filename) throws Exception{
        File root = new File(filename);
        File f2 = new File(root, "hmacFile");

        if(!f2.exists()){
            throw new FileNotFoundException("hmacFile is not found");
        }

        String s = new String(read_from_file(f2), "UTF-8");
        String[] content = s.split("\n");

        content[i] = "";
        String newHmacContent = String.join("\n", content);

        save_to_file(newHmacContent.getBytes("UTF-8"), f2);
    }

    /**
     * Steps to consider... <p>
     *  - check if metadata file size is valid <p>
     *  - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {
        final long requiredSize = Config.BLOCK_SIZE; // expected size in bytes
        File file = new File(file_name);
        File meta = new File(file, "0");
        long fileSize = meta.length();
        if (fileSize == requiredSize)
        {
//            System.out.println("Metadata file size is valid.");
            String s = new String (read_from_file(meta));
            //System.out.println(s);
            String[] stringArray = s.split("\n");
            //System.out.println(stringArray);
            return stringArray[1];
        }
        else {
            //System.out.println("Metadata file size is not valid.");
            throw new Exception("Metadata file size not valid");
        }
    }


    public String PasswordValidationCheck(String filename, String password) throws Exception{
        //to check password
        File root = new File(filename);
        File meta1 = new File(root, "0");
        String s = new String(read_from_file(meta1), "UTF-8");
        String[] strs = s.split("\n");
        String Salt = strs[2];
        String pass_salt = Salt + password;
        byte[] hashpwd = hash_SHA256(pass_salt.getBytes("UTF-8"));
        String hashedPassword = Base64.getEncoder().encodeToString(hashpwd);
        String hashInMeta = strs[3];
        if (hashedPassword.equals(hashInMeta)) {
//            System.out.println("same");
            return "same";
        } else {
//            System.out.println("not same");
            throw new PasswordIncorrectException();
        }
    }

    /*private byte[] generateIV(byte[] nonce) throws NoSuchAlgorithmException{
        byte[] iv = new byte[128 / 8];
        System.arraycopy(nonce, 0, iv, 0, nonce.length);
        System.out.println("g_iv "+ iv);
        System.out.println("g_nonce "+ nonce);
        return iv;
    }*/


    private byte[] incrementIV(byte[] iv) {
        for (int i = iv.length - 1; i >= 0; i--) {
            iv[i]++;
            if (iv[i] != 0) break;
        }
        return iv;
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
        String pwd_check = PasswordValidationCheck(file_name, password);
        if (pwd_check=="same") {
            File file = new File(file_name);
            File meta = new File(file, "0");
            String s = new String (read_from_file(meta));
            String[] stringArray = s.split("\n");
            byte[] length = Base64.getDecoder().decode(stringArray[0].trim());
            String len = new String(length, "UTF-8");
//            System.out.println(len);
            return Integer.parseInt(len);
        }
//        else{
////            System.out.println("Passwords not same");
//        }
        return -1;
    }

    /*public byte[] decryptAESCTR(byte[] ciphertext, byte[] iv, byte[] key){

        return null;
    }*/

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
        String pwd_check = PasswordValidationCheck(file_name, password);
        if(pwd_check.equals("same")) {
            File root = new File(file_name);
            int file_length = length(file_name, password);
            //System.out.println("\nFile length: "+ file_length);
            if (starting_position + len > file_length) {
                throw new Exception();
            }

            int start_block = starting_position / Config.BLOCK_SIZE;

            int end_block = (starting_position + len) / Config.BLOCK_SIZE;
            //System.out.println("start block "+start_block);
            //System.out.println("end block "+end_block);
            File meta = new File(root, "0");
            String metaStr = new String(read_from_file(meta), "UTF-8");
            String[] metaArr = metaStr.split("\n");
            //byte[] metaBytes = read_from_file(meta);

            //System.out.println("\nmeta bytes: "+ Arrays.toString(metaStr.getBytes("UTF-8)));
            //System.out.println("\n meta after trimming: "+ Base64.getDecoder().decode(metaStr.tr.trim()im()));

            byte[] iv = Base64.getDecoder().decode(metaArr[4].trim());
            //System.out.println("\nIV in write: " + Arrays.toString(iv));

            byte[] secretKey1 = Base64.getDecoder().decode(metaArr[5].trim());
            //System.out.println("\nSecret Key in write: " + Arrays.toString(secretKey1));
            String contentInblocks="";

            for (int i = start_block + 1; i <= end_block + 1; i++) {
                String cipherText = new String(read_from_file(new File(root, Integer.toString(i))), "UTF-8"); //), "ISO-8859-1");
                byte[] cipherContent = Base64.getDecoder().decode(cipherText.trim());
                byte[] decryptedContent = AESCTRdecrypt(cipherContent, iv, secretKey1);
                //System.out.println("\nDecrypted content in bytes: "+Arrays.toString(decryptedContent));
                //String decryptedContentAsString = Base64.getEncoder().encodeToString(decryptedContent);
                String decryptedContentAsString = new String(decryptedContent, "UTF-8");
                contentInblocks += decryptedContentAsString;
                //System.out.println("\nDecrypted content after Encoding as String: "+decryptedContentAsString);
            }
            //System.out.println("\n content in blocks: " + contentInblocks);
            int sp = starting_position-(start_block*Config.BLOCK_SIZE);
            int ep = sp+len;
            //System.out.println("\n content required: "+ contentInblocks.substring(sp, ep));
            //byte[] decodedContent=Base64.getDecoder().decode(contentInb.trim()locks);
            //System.out.println("\nDecoded content in blocks: "+Arrays.toString(decodedContent));
            //byte[] decodedContent = contentInblocks.getBytes("UTF-8);
            String decodedSubString=contentInblocks.substring(sp,ep);
            //System.out.println("\ndecoded Substring as bytes: "+Arrays.toString(decodedSubString.getBytes("UTF-8)));
            return decodedSubString.getBytes("UTF-8");
        }
        return null;
    }


    // method for encryption using AES-CTR method
    public byte[] AESCTR(byte[] message, byte[] iv, byte[] key) throws Exception{
        // padding content
        int padding_amt = 16 - message.length % 16;
        //System.out.println("\nPadding length needed: "+padding_amt);
        byte[] padding = new byte[padding_amt];
        Arrays.fill(padding, (byte) padding_amt);
        byte[] contentWithPadding = Arrays.copyOf(message, message.length + padding_amt);
        System.arraycopy(padding, 0, contentWithPadding, message.length, padding_amt);

        // Divide the padded content into 16-byte blocks
        int contentBlocks = contentWithPadding.length / 16;
        byte[][] blocks = new byte[contentBlocks][16];
        for (int i = 0; i < contentBlocks; i++) {
            System.arraycopy(contentWithPadding, i * 16, blocks[i], 0, 16);
        }

        //String messageAsString = new String(message);
//        System.out.println("Content: "+ messageAsString);

        // blocks.length = 65
        //System.out.println("\nIV in write: " + Arrays.toString(iv));
        //System.out.println("\nSecret Key in write: " + Arrays.toString(key));

        byte[][] ivBlocks = new byte[blocks.length][16];
        byte[] counter = Arrays.copyOf(iv, 16);
        //System.out.println("\n1.1 " );

        for (int i = 0; i < blocks.length; i++) {
            ivBlocks[i] = encript_AES(counter, key);
            incrementIV(counter);
            //System.out.println(Arrays.toString(ivBlocks[i]));
            //System.out.println("\n1... " );
        }
        //System.out.println("\n1.2 " );

        byte[] encryptedContent = new byte[contentWithPadding.length];
        //System.out.println("encryptedContent: "+ encryptedContent);

        //System.out.println("\n1.3 " );

        for (int i = 0; i < blocks.length; i++) {
            byte[] xorBlock = new byte[16];
            for (int j = 0; j < 16; j++) {
                xorBlock[j] = (byte) (blocks[i][j] ^ ivBlocks[i][j]);
            }
            System.arraycopy(xorBlock, 0, encryptedContent, i * 16, 16);
            //System.out.println("\n1.4 " );
        }
        //System.out.println("\n Encrypted Content: "+ Arrays.toString(encryptedContent));
        //System.out.println("\n1.5 " );
        //System.out.println("\nContent: "+ Base64.getEncoder().encodeToString(encryptedContent) );

        //System.out.println("Encrypted content after xor: " + encryptedContent);
        return encryptedContent;
    }

    public byte[] AESCTRdecrypt(byte[] encryptedContent, byte[] iv, byte[] key) throws Exception {

        int contentBlocks = encryptedContent.length / 16;
        byte[][] blocks = new byte[contentBlocks][16];
        for (int i = 0; i < contentBlocks; i++) {
            System.arraycopy(encryptedContent, i * 16, blocks[i], 0, 16);
        }


        byte[][] ivBlocks = new byte[blocks.length][16];
        byte[] counter = Arrays.copyOf(iv, 16);
        for (int i = 0; i < blocks.length; i++) {
            ivBlocks[i] = encript_AES(counter, key);
            incrementIV(counter);
        }


        byte[] decryptedContent = new byte[encryptedContent.length];
        for (int i = 0; i < blocks.length; i++) {
            byte[] xorBlock = new byte[16];
            for (int j = 0; j < 16; j++) {
                xorBlock[j] = (byte) (blocks[i][j] ^ ivBlocks[i][j]);
            }
            System.arraycopy(xorBlock, 0, decryptedContent, i * 16, 16);
        }


        int paddingLength = decryptedContent[decryptedContent.length - 1];
        byte[] plainTextFinal = Arrays.copyOfRange(decryptedContent, 0, decryptedContent.length - paddingLength);

        return plainTextFinal;
    }


    /**
     * Steps to consider...:<p>
     *	- verify password <p>
     *  - check if requested starting position and length are valid <p>
     *  - ### main procedure for update the encrypted content ### <p>
     *  - compute new HMAC and update metadata
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        String pwd_check = PasswordValidationCheck(file_name, password);
        if(pwd_check.equals("same")){
            //System.out.println("\nWrite block");
            String str_content = new String(content, "UTF-8"); //, "ISO-8859-1");
            File root = new File(file_name);
            int file_length = length(file_name, password);
            //System.out.println("\nFile length in write: "+file_length);

            if (starting_position > file_length) {
                throw new Exception();
            }

            File meta = new File(root, "0");
            String metaStr = new String(read_from_file(meta), "UTF-8");
            String[] metaArr = metaStr.split("\n");

            byte[] iv = Base64.getDecoder().decode(metaArr[4].trim());
            //System.out.println("\nIV in write: " + Arrays.toString(iv));

            byte[] secretKey1 = Base64.getDecoder().decode(metaArr[5].trim());
            //System.out.println("\nSecret Key in write: " + Arrays.toString(secretKey1));


            int len = str_content.length();
            int encryptedContentLength = 0;
            int start_block = starting_position / Config.BLOCK_SIZE;
            int end_block = (starting_position + len) / Config.BLOCK_SIZE;

            for (int i = start_block + 1; i <= end_block + 1; i++) {
                int sp = (i - 1) * Config.BLOCK_SIZE - starting_position;
                int ep = (i) * Config.BLOCK_SIZE - starting_position;
                String prefix = "";
                String postfix = "";
                if (i == start_block + 1 && starting_position != start_block * Config.BLOCK_SIZE) {
                    if(sp!=0) {
                        String prefixSTR = new String(read_from_file(new File(root, Integer.toString(i))), "UTF-8");
                        byte[] prefixInBytes = Base64.getDecoder().decode(prefixSTR.trim());
                        byte[] decrypted_prefix = AESCTRdecrypt(prefixInBytes, iv, secretKey1);
                        //int paddingLength = decrypted_prefix[decrypted_prefix.length-1];
                        //byte[] decryptedPrefix = Arrays.copyOfRange(decrypted_prefix, 0, decrypted_prefix.length-paddingLength);
                        prefix = (new String(decrypted_prefix, "UTF-8").trim()).substring(0, starting_position - start_block * Config.BLOCK_SIZE);
                        //prefix = new String(read_from_file(new File(root, Integer.toString(i))));
                        //prefix = prefix.substring(0, starting_position - start_block * Config.BLOCK_SIZE);
                        sp = Math.max(sp, 0);
                    }
                }

                if (i == end_block + 1) {
                    File end = new File(root, Integer.toString(i));
                    if (end.exists()) {
                        String postfixSTR = new String(read_from_file(new File(root, Integer.toString(i))), "UTF-8");
                        byte[] postfixInBytes = Base64.getDecoder().decode(postfixSTR.trim());
                        byte[] decrypted_postfix = AESCTRdecrypt(postfixInBytes, iv, secretKey1);
                        //int paddingLength2 = decrypted_postfix[decrypted_postfix.length-1];
                        //byte[] decryptedPostfix = Arrays.copyOfRange(decrypted_postfix, 0, decrypted_postfix.length-paddingLength2);
                        postfix = (new String(decrypted_postfix, "UTF-8")).trim();
                        //postfix = byteArray2String(read_from_file(new File(root, Integer.toString(i))));

                        if (postfix.length() > starting_position + len - end_block * Config.BLOCK_SIZE) {
                            postfix = postfix.substring(starting_position + len - end_block * Config.BLOCK_SIZE);
                        } else {
                            postfix = "";
                        }
                    }
                    ep = Math.min(ep, len);
                }

                String newContent = prefix + str_content.substring(sp, ep) + postfix;
                byte[] newContentBytes = newContent.getBytes("UTF-8");
                byte[] encryptedContent = AESCTR(newContentBytes, iv, secretKey1);
                String toWrite = Base64.getEncoder().encodeToString(encryptedContent);

                //System.out.println("\nNew content bytes: "+Arrays.toString(newContentBytes));

                while (toWrite.length() < Config.BLOCK_SIZE) {
                    toWrite += '\0';
                }
                //System.out.println("\ntoWrite length: "+toWrite.length());
                //System.out.println("\nencryptedContent length: "+encryptedContent.length);
                encryptedContentLength += encryptedContent.length;
                //System.out.println("\n running sum of length: "+ encryptedContentLength);

                byte[] HMACCalculated = calculateHMAC(secretKey1, toWrite.getBytes("UTF-8"));
                String HMACstring = Base64.getEncoder().encodeToString(HMACCalculated);
                //System.out.println("HMAC in write: " + HMACstring);
                updateHMAC(HMACstring, i, file_name);

                save_to_file(toWrite.getBytes("UTF-8"), new File(root, Integer.toString(i)));
            }

            if (content.length + starting_position > length(file_name, password)) {
                String s = new String(read_from_file(new File(root, "0")), "UTF-8"); // "ISO-8859-1");
                String[] strs = s.split("\n");
                int newLen = content.length + starting_position;
                strs[0] = Base64.getEncoder().encodeToString((Integer.toString(newLen)).getBytes("UTF-8"));
                //System.out.println("\nUpdated length in meta in write: "+strs[0]);
                String toWrite = "";
                for (String t : strs) {
                    toWrite += t + "\n";
                }
                while (toWrite.length() < Config.BLOCK_SIZE) {
                    toWrite += '\0';
                }
                toWrite = toWrite.trim();
                //update hmac of metadata since its length is changed
                byte[] metaHMACupdation = calculateHMAC(secretKey1, toWrite.getBytes("UTF-8"));
                String metaHMACupdatedString = Base64.getEncoder().encodeToString(metaHMACupdation);
                updateHMAC(metaHMACupdatedString, 0, file_name);


                save_to_file(toWrite.getBytes("UTF-8"), new File(root, "0"));

            }
        }
    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        String pwd_check = PasswordValidationCheck(file_name, password);
        if(pwd_check.equals("same")){
            File root = new File(file_name);
            File hmacfile = new File(root, "hmacFile");
            String hmacStored = new String(read_from_file(hmacfile), "UTF-8");
            String[] hmacValues = hmacStored.split("\n");
            //System.out.println("\nhmac file: "+hmacStored);
            long numBlocks = hmacValues.length;
            //System.out.println("\nnumber of blocks: "+numBlocks);

            File meta = new File(root, "0");
            String metaStr = new String(read_from_file(meta), "UTF-8");
            String[] metaArr = metaStr.split("\n");

            byte[] secretKey1 = Base64.getDecoder().decode(metaArr[5].trim());

            for(int i=0; i<numBlocks; i++){
                File file = new File(root, (i+""));
                String fileStr = new String(read_from_file(file), "UTF-8"); //, "ISO-8859-1");
                byte[] HMACcalculation = calculateHMAC(secretKey1, fileStr.getBytes("UTF-8"));
                String HMACcalculatedStr = Base64.getEncoder().encodeToString(HMACcalculation);
                if(!HMACcalculatedStr.equals(hmacValues[i])){
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Steps to consider... <p>
     *  - verify password <p>
     *  - truncate the content after the specified length <p>
     *  - re-pad, update metadata and HMAC <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {
        //System.out.println("\n Cut block running...");
        //System.out.println("\n Cut block running  length..."+length);
        String pwd_check = PasswordValidationCheck(file_name, password);
        if(pwd_check.equals("same")){
            File root = new File(file_name);

            File meta = new File(root, "0");
            String metaStr = new String(read_from_file(meta), "UTF-8");
            String[] metaArr = metaStr.split("\n");

            byte[] iv = Base64.getDecoder().decode(metaArr[4].trim());
            //System.out.println("\nIV in write: " + Arrays.toString(iv));

            byte[] secretKey1 = Base64.getDecoder().decode(metaArr[5].trim());
            //System.out.println("\nSecret Key in write: " + Arrays.toString(secretKey1));

            int file_length = length(file_name, password);
            //System.out.println("\nFile Length (before): " + file_length);
            if (length > file_length) {
                throw new Exception();
            }
            int end_block = (length) / Config.BLOCK_SIZE;
            //System.out.println("\nEnd Block: " + end_block);

            File file = new File(root, Integer.toString(end_block + 1));
            // test
            String content=new String(read_from_file(file), "UTF-8"); //, "ISO-8859-1");
            byte[] decodedContent=Base64.getDecoder().decode(content.trim());
            //System.out.println("\n content - "+content);
            //System.out.println("\n decodedContent - "+new String(decodedContent));
            // test ends
            byte[] fileContent = read_from_file(file);
            //System.out.println("\n1 ");
            byte[] decryptedContent = AESCTRdecrypt(decodedContent, iv, secretKey1);
            //System.out.println("\n decryptedContent - "+new String(decryptedContent));
            //System.out.println("\n2");
            String decrContent = new String(decryptedContent, "UTF-8");
            // String decrContent = Base64.getEncoder().encodeToString(decryptedContent);
            //System.out.println("\n3 decrContent - "+decrContent);
            decrContent = decrContent.substring(0, length-end_block*Config.BLOCK_SIZE);
        /*while (decrContent.length() < Config.BLOCK_SIZE) {
            decrContent += '\0';
        }*/

            byte[] NewContent = decrContent.getBytes("UTF-8");
            //System.out.println("\n5.5");
            byte[] encryptedNewcontent = AESCTR(NewContent, iv, secretKey1);
            String encodedString = Base64.getEncoder().encodeToString(encryptedNewcontent);

            //System.out.println("\n6");

            save_to_file(encodedString.getBytes("UTF-8"), file);

            byte[] updatedHMAC = calculateHMAC(secretKey1, encodedString.getBytes("UTF-8"));
            String updatedHMACstr = Base64.getEncoder().encodeToString(updatedHMAC);
            updateHMAC(updatedHMACstr, end_block+1, file_name);

            //System.out.println("HMAC in cut: " + updatedHMACstr);

            //System.out.println("\n7");
            int cur = end_block + 2;
            file = new File(root, Integer.toString(cur));
            while (file.exists()) {
                file.delete();
                deleteHMAC(cur, file_name);
                cur++;
                file = new File(root, Integer.toString(cur));
                //System.out.println("\n..");
            }
            //System.out.println("\n9");

            //update meta data
            String s = new String(read_from_file(new File(root, "0")), "UTF-8"); //, "ISO-8859-1");
            //System.out.println("\n10");
            String[] strs = s.split("\n");
            //System.out.println("\n11");
            strs[0] = Base64.getEncoder().encodeToString((Integer.toString(length)).getBytes("UTF-8"));
            //System.out.println("\nupdated length for meta in cut: "+strs[0]);
            //System.out.println("\n12");
            String toWrite = "";
            for (String t : strs) {
                toWrite += t + "\n";
                //System.out.println("\n...");
            }
            while (toWrite.length() < Config.BLOCK_SIZE) {
                toWrite += '\0';
                //System.out.println("\n!!");
            }
            //System.out.println("\n13");
            //toWrite = toWrite.trim();

            // HMAC update for meta after cutting the file
            byte[] metaHMACupdation = calculateHMAC(secretKey1, toWrite.getBytes("UTF-8"));
            String metaHMACupdatedString = Base64.getEncoder().encodeToString(metaHMACupdation);
            updateHMAC(metaHMACupdatedString, 0, file_name);

            save_to_file(toWrite.getBytes("UTF-8"), new File(root, "0"));

        }
    }
}
