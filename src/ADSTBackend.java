import okhttp3.*;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Numeric;

// AWS Imports
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.core.sync.RequestBody;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ADSTBackend {

    // --- Configuration (UPDATE THESE) ---
    private static final String PINATA_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiI1MTkzYjhkNi04MjFkLTQ1MTktYTNiMi0xNWE3NWNjZDcwYjAiLCJlbWFpbCI6InN5ZWRyaWFzdWRkaW4ucy5zQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJwaW5fcG9saWN5Ijp7InJlZ2lvbnMiOlt7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6IkZSQTEifSx7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6Ik5ZQzEifV0sInZlcnNpb24iOjF9LCJtZmFfZW5hYmxlZCI6ZmFsc2UsInN0YXR1cyI6IkFDVElWRSJ9LCJhdXRoZW50aWNhdGlvblR5cGUiOiJzY29wZWRLZXkiLCJzY29wZWRLZXlLZXkiOiI0YmNiNzU4YzRmOWIxNDg4YjVmMSIsInNjb3BlZEtleVNlY3JldCI6IjJkNzk3MGE2MWY1NjExZWY0NjQ1ZTI1ZDY1N2E5ZWIxZWVhNTllOGI3MzFjOTJjYTg0YjdjNjBiZmU0OTBiYTkiLCJleHAiOjE4MTc0NTcxNDd9.lCRC7g8sfBd9KsfIVYeB3vJ6Dxw_Cph8iD00UJS5knk"; // Paste your Pinata JWT here
    private static final String CONTRACT_ADDRESS = "0x9D7f74d0C41E726EC95884E0e97Fa6129e3b5E99"; // Paste your NEW Smart Contract Address
    private static final String PRIVATE_KEY = "38cea97b600035168a73d8ba391285de33cfd827b158334503df33c4d93c6b13"; // Paste your Sepolia Private Key here
    private static final String ALCHEMY_RPC_URL = "https://eth-sepolia.g.alchemy.com/v2/..."; // Paste your RPC URL
    private static final String AES_SECRET_KEY = "1234567890123456"; // Must be exactly 16 chars
    private static final String AWS_BUCKET_NAME = "adst-standard-storage"; // Your S3 Bucket Name
    private static final String AWS_ACCESS_KEY_ID = "YOUR_AWS_ACCESS_KEY_HERE";
    private static final String AWS_SECRET_ACCESS_KEY = "YOUR_AWS_SECRET_KEY_HERE";
    // --- Classifier Patterns ---
    private static final String[] SENSITIVE_PATTERNS = {
        "\\b(?:\\d[ -]*?){13,16}\\b",
        "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
        "(?i)(password|passwd|private_key|api_key|secret).{0,10}[:=].{1,50}"
    };

    public static void main(String[] args) {
        try {
            System.out.println("=== ADST PIPELINE EXECUTOR ===");
            String filePath = "test_document.txt";
            Files.writeString(Paths.get(filePath), "This is a regular public file content.", StandardCharsets.UTF_8);
            
            // 1. Execute routing and capture the generated fileId
            String fileId = executeRoutingPipeline(filePath);
            
            System.out.println("\n--- TESTING RETRIEVAL & DECRYPTION ---");
            
            // 2. Retrieve and decrypt the file using the ID
            String originalText = retrieveAndDecryptLocalFile(fileId);
            
            System.out.println("Decrypted Content Output: " + originalText);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }           

    // --- CORE ROUTING ENGINE ---
    public static String executeRoutingPipeline(String filePath) throws Exception {
        String payload = Files.readString(Paths.get(filePath));
        String fileId = "ADST-" + UUID.randomUUID().toString();
        System.out.println("[Executor] Generated File ID: " + fileId);

        boolean isSensitive = classifyData(payload);
        String encryptedPayload = encryptAES(payload, AES_SECRET_KEY);
        String dataHash = generateSHA256(payload);

     // ... (inside executeRoutingPipeline) ...

        if (isSensitive) {
            System.out.println("--> Path A Selected: SENSITIVE. Routing to Blockchain/IPFS.");
            File tempFile = new File("temp_ipfs.dat");
            Files.writeString(tempFile.toPath(), encryptedPayload, StandardCharsets.UTF_8);
            
            String ipfsCid = uploadToPinata(tempFile);
            storeOnChain(fileId, ipfsCid, dataHash);
            
            Files.deleteIfExists(tempFile.toPath()); // Cleanup
        } else {
            System.out.println("--> Path B Selected: STANDARD. Routing to Local Folder.");
            // Change this line from uploadToAWS to saveToLocalFolder
            saveToLocalFolder(fileId, encryptedPayload); 
        }

        return fileId;
    }

    // --- AWS S3 STANDARD STORAGE EXECUTION ---
 // --- LOCAL STANDARD STORAGE SIMULATOR (Replaces AWS S3 temporarily) ---
    private static void saveToLocalFolder(String fileId, String encryptedData) {
        System.out.println("[Local Storage Executor] Initializing local file write...");
        try {
            // Define the local directory path
            String directoryPath = "Standard_Storage_Local";
            File directory = new File(directoryPath);
            
            // Create the directory if it doesn't exist
            if (!directory.exists()) {
                directory.mkdir();
            }

            // Create the file path using the fileId
            String filePath = directoryPath + "/" + fileId + ".dat";
            
            // Write the encrypted data to the file
            Files.writeString(Paths.get(filePath), encryptedData, StandardCharsets.UTF_8);
            
            System.out.println("SUCCESS! Encrypted standard file secured locally at: " + filePath);
        } catch (Exception e) {
            System.err.println("Local Storage Failed: " + e.getMessage());
        }
    }
 // --- LOCAL RETRIEVAL & DECRYPTION ENGINE ---
    public static String retrieveAndDecryptLocalFile(String fileId) {
        System.out.println("[Retriever] Searching local storage for File ID: " + fileId);
        try {
            String filePath = "Standard_Storage_Local/" + fileId + ".dat";
            File file = new File(filePath);
            
            if (!file.exists()) {
                System.err.println("Retrieval Failed: File ID not found in local storage.");
                return null;
            }

            // Read the encrypted Base64 string from the file
            String encryptedData = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            
            // Decrypt the payload
            String decryptedPayload = decryptAES(encryptedData, AES_SECRET_KEY);
            
            System.out.println("SUCCESS! File successfully retrieved and decrypted.");
            return decryptedPayload;

        } catch (Exception e) {
            System.err.println("Decryption Exception: " + e.getMessage());
            return null;
        }
    }

    // --- HELPER: AES DECRYPTION ---
    private static String decryptAES(String encryptedData, String secretKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedBytes), StandardCharsets.UTF_8);
    }

    // --- PINATA IPFS UPLOAD ---
    private static String uploadToPinata(File file) throws Exception {
        OkHttpClient client = new OkHttpClient();
        okhttp3.RequestBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", file.getName(),
                        okhttp3.RequestBody.create(file, MediaType.parse("application/octet-stream")))
                .build();

        Request request = new Request.Builder()
                .url("https://api.pinata.cloud/pinning/pinFileToIPFS")
                .post(requestBody)
                .addHeader("Authorization", "Bearer " + PINATA_JWT)
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) throw new RuntimeException("Pinata Upload Failed: " + response);
            return response.body().string().split("\"IpfsHash\":\"")[1].split("\"")[0];
        }
    }

    // --- BLOCKCHAIN STORAGE ---
    private static boolean storeOnChain(String fileId, String ipfsCid, String dataHash) {
        Web3j web3j = Web3j.build(new HttpService(ALCHEMY_RPC_URL));
        try {
            Credentials credentials = Credentials.create(PRIVATE_KEY);
            String dataTypeString = "SENSITIVE_DATA";

            Function function = new Function(
                    "storeSensitiveData",
                    Arrays.asList(
                            new Utf8String(fileId), 
                            new Utf8String(ipfsCid), 
                            new Utf8String(dataHash), 
                            new Utf8String(dataTypeString)
                    ),
                    Collections.emptyList()
            );
            
            String encodedFunction = FunctionEncoder.encode(function);

            EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
                    credentials.getAddress(), DefaultBlockParameterName.PENDING).send();
            
            BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
            BigInteger gasLimit = BigInteger.valueOf(1000000); 

            RawTransaction rawTransaction = RawTransaction.createTransaction(
                    ethGetTransactionCount.getTransactionCount(), 
                    gasPrice, 
                    gasLimit, 
                    CONTRACT_ADDRESS, 
                    encodedFunction);
            
            byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, 11155111, credentials);
            EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(Numeric.toHexString(signedMessage)).send();
            
            if (ethSendTransaction.hasError()) {
                System.out.println("[Blockchain Error]: " + ethSendTransaction.getError().getMessage());
                return false;
            }

            String txHash = ethSendTransaction.getTransactionHash();
            System.out.println("Broadcast successful. Tx Hash: " + txHash);

            int attempt = 0;
            while (attempt < 30) {
                Optional<TransactionReceipt> receiptOpt = web3j.ethGetTransactionReceipt(txHash).send().getTransactionReceipt();
                if (receiptOpt.isPresent()) {
                    TransactionReceipt receipt = receiptOpt.get();
                    if ("0x1".equalsIgnoreCase(receipt.getStatus())) {
                        System.out.println("SUCCESS! ADST routing record securely anchored on-chain.");
                        return true;
                    } else {
                        System.out.println("[Transaction Reverted] EVM execution failed.");
                        return false;
                    }
                }
                attempt++;
                Thread.sleep(3000);
            }
        } catch (Exception e) {
            System.out.println("[Transaction Exception]: " + e.getMessage());
        } finally {
            web3j.shutdown();
        }
        return false;
    }

    // --- HELPER MODULES ---
    private static boolean classifyData(String data) {
        for (String regex : SENSITIVE_PATTERNS) {
            if (Pattern.compile(regex).matcher(data).find()) return true;
        }
        return false;
    }

    private static String encryptAES(String data, String secretKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private static String generateSHA256(String base) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(base.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}