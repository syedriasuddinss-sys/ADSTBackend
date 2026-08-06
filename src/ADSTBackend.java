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
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Numeric;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ADSTBackend {

    // --- Configuration ---
    private static final String PINATA_JWT = System.getenv("PINATA_JWT") != null ? System.getenv("PINATA_JWT") : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiI1MTkzYjhkNi04MjFkLTQ1MTktYTNiMi0xNWE3NWNjZDcwYjAiLCJlbWFpbCI6InN5ZWRyaWFzdWRkaW4ucy5zQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJwaW5fcG9saWN5Ijp7InJlZ2lvbnMiOlt7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6IkZSQTEifSx7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6Ik5ZQzEifV0sInZlcnNpb24iOjF9LCJtZmFfZW5hYmxlZCI6ZmFsc2UsInN0YXR1cyI6IkFDVElWRSJ9LCJhdXRoZW50aWNhdGlvblR5cGUiOiJzY29wZWRLZXkiLCJzY29wZWRLZXlLZXkiOiI0YmNiNzU4YzRmOWIxNDg4YjVmMSIsInNjb3BlZEtleVNlY3JldCI6IjJkNzk3MGE2MWY1NjExZWY0NjQ1ZTI1ZDY1N2E5ZWIxZWVhNTllOGI3MzFjOTJjYTg0YjdjNjBiZmU0OTBiYTkiLCJleHAiOjE4MTc0NTcxNDd9.lCRC7g8sfBd9KsfIVYeB3vJ6Dxw_Cph8iD00UJS5knk";
    private static final String CONTRACT_ADDRESS = "0xac91a07e79F7300153aD54e9b61F7B6FeCC4d7BE"; 
    private static final String PRIVATE_KEY = System.getenv("SEPOLIA_PRIVATE_KEY") != null ? System.getenv("SEPOLIA_PRIVATE_KEY") : "38cea97b600035168a73d8ba391285de33cfd827b158334503df33c4d93c6b13";
    private static final String ALCHEMY_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com";
    private static final String AES_SECRET_KEY = System.getenv("AES_SECRET_KEY") != null ? System.getenv("AES_SECRET_KEY") : "x!A%C*F-JaNdRgUkXp2s5v8y/B?E(G+K"; 

    // --- Classifier Patterns (Security Regex Array) ---
    private static final String[] SENSITIVE_PATTERNS = {
        "\\b(?:\\d[ -]*?){13,16}\\b",                   // Credit Card
        "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b",       // 12-Digit Government IDs
        "\\b[A-Z]{5}[0-9]{4}[A-Z]{1}\\b",               // PAN Formats
        "\\b[A-Z][1-9]\\d{6}\\b",                       // Passport Formats
        "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", // Email
        "(?i)(password|passwd|private_key|api_key|secret).{0,10}[:=].{1,50}" // Credentials
    };

    public static void main(String[] args) {
        try {
            System.out.println("=== ADST PIPELINE EXECUTION STARTED ===");

            // 1. Setup a test payload file
            String filePath = "upload_test.txt";
            String testData = "Username: sys_admin | password=SuperSecret_99!"; 
            Files.writeString(Paths.get(filePath), testData, StandardCharsets.UTF_8);
            
            // 2. Execute Upload & Encryption Pipeline
            String generatedFileId = executeRoutingPipeline(filePath);
            
            // 3. Execute Retrieval, Decryption & Verification Pipeline using the generated ID
            if (generatedFileId != null) {
                retrieveAndVerifyData(generatedFileId);
            }
            
            // Cleanup local temp files
            Files.deleteIfExists(Paths.get(filePath));
            Files.deleteIfExists(Paths.get("temp_ipfs_upload.dat"));

        } catch (Exception e) {
            System.err.println("[Main Execution Status]: " + e.getMessage());
        }
    }

    // --- PHASE 1: UPLOAD & ENCRYPTION PIPELINE ---
    public static String executeRoutingPipeline(String filePath) throws Exception {
        System.out.println("\n[Executor] Reading local payload...");
        String payload = Files.readString(Paths.get(filePath));
     // Change this line inside executeRoutingPipeline():
        String fileId = "ADST-" + UUID.randomUUID().toString();

        System.out.println("[Executor] Scanning data for sensitive patterns...");
        boolean isSensitive = classifyData(payload);

        String finalPayload;
        if (isSensitive) {
            System.out.println("--> Path A Selected: SENSITIVE. Applying AES-256 Encryption.");
            finalPayload = encryptAES(payload, AES_SECRET_KEY); 
        } else {
            System.out.println("--> Path B Selected: STANDARD. Proceeding unencrypted.");
            finalPayload = payload;
        }

        System.out.println("[Executor] Generating SHA-256 Hash for on-chain integrity...");
        String dataHash = generateSHA256(payload);

        System.out.println("[Executor] Routing payload to Pinata IPFS Gateway...");
        File tempFile = new File("temp_ipfs_upload.dat");
        Files.writeString(tempFile.toPath(), finalPayload, StandardCharsets.UTF_8);
        String ipfsCid = uploadToPinata(tempFile);
        System.out.println("Successfully secured & pinned. CID: " + ipfsCid);

        System.out.println("[Executor] Anchoring storage record to Sepolia Blockchain...");
        boolean success = storeOnChain(fileId, ipfsCid, dataHash, isSensitive);
        
        if (success) {
            System.out.println("[Executor] Upload Pipeline Complete. File ID: " + fileId);
            return fileId;
        }
        return null;
    }

 // --- PHASE 2: RETRIEVAL & VERIFICATION PIPELINE ---
    public static void retrieveAndVerifyData(String fileId) {
        System.out.println("\n[Retriever] Initiating secure retrieval for File ID: " + fileId);
        Web3j web3j = Web3j.build(new HttpService(ALCHEMY_RPC_URL));
        
        try {
            // Give the RPC node 3 seconds to sync the newly mined block state
            Thread.sleep(3000); 

            // 1. Query the Smart Contract for metadata (IPFS CID and Data Hash)
            Function function = new Function(
                    "getSensitiveData",
                    Arrays.asList(new Utf8String(fileId)),
                    Arrays.asList(
                            new TypeReference<Utf8String>() {},
                            new TypeReference<Utf8String>() {},
                            new TypeReference<Utf8String>() {},
                            new TypeReference<org.web3j.abi.datatypes.generated.Uint256>() {}
                    )
            );

            String encodedFunction = FunctionEncoder.encode(function);
            EthCall response = web3j.ethCall(
                    org.web3j.protocol.core.methods.request.Transaction.createEthCallTransaction(
                            null, CONTRACT_ADDRESS, encodedFunction),
                    DefaultBlockParameterName.LATEST).send();

            List<org.web3j.abi.datatypes.Type> result = org.web3j.abi.FunctionReturnDecoder.decode(
                    response.getValue(), function.getOutputParameters());

            if (result.isEmpty() || result.get(0).getValue().toString().isEmpty()) {
                System.out.println("[Retriever Error]: File ID not found on-chain. Check your Smart Contract getter function.");
                return;
            }

            // Trim out any potential EVM null padding bytes
            String ipfsCid = result.get(0).getValue().toString().trim();
            String onChainHash = result.get(1).getValue().toString().trim();
            String dataType = result.get(2).getValue().toString().trim();

            System.out.println("[Retriever] On-chain record found.");
            System.out.println(" -> IPFS CID: " + ipfsCid);
            System.out.println(" -> Expected Hash: " + onChainHash);
            System.out.println(" -> Data Classification: " + dataType);

            // 2. Download the payload (Switched to ipfs.io to avoid Pinata 403 blocks)
            System.out.println("[Retriever] Downloading payload from IPFS gateway...");
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://ipfs.io/ipfs/" + ipfsCid) 
                    .build();

            String downloadedPayload;
            try (Response ipfsResponse = client.newCall(request).execute()) {
                if (!ipfsResponse.isSuccessful()) {
                    throw new RuntimeException("IPFS Download Failed (HTTP " + ipfsResponse.code() + "). The gateway might be busy.");
                }
                downloadedPayload = ipfsResponse.body().string().trim();
            }

            // 3. Decrypt or Read Payload (Safely matching the trimmed string)
            String finalDecryptedText;
            if (dataType.contains("SENSITIVE_DATA")) {
                System.out.println("[Retriever] Decrypting payload using local AES key...");
                finalDecryptedText = decryptAES(downloadedPayload, AES_SECRET_KEY);
            } else {
                finalDecryptedText = downloadedPayload;
            }
            System.out.println(" -> Resolved Content: " + finalDecryptedText);

            // 4. Verify Integrity (Hash Check against Plaintext)
            System.out.println("[Retriever] Verifying cryptographic hash against blockchain record...");
            String currentHash = generateSHA256(finalDecryptedText).trim();

            if (currentHash.equalsIgnoreCase(onChainHash)) {
                System.out.println("SUCCESS! Data integrity verified. The payload has not been tampered with.");
            } else {
                System.out.println("WARNING: Integrity check failed! Hash mismatch detected.");
            }

        } catch (Exception e) {
            System.out.println("[Retrieval Exception]: " + e.getMessage());
        } finally {
            web3j.shutdown();
        }
    }

    // --- Helper Modules ---

    private static boolean classifyData(String data) {
        for (String regex : SENSITIVE_PATTERNS) {
            Matcher matcher = Pattern.compile(regex).matcher(data);
            if (matcher.find()) return true;
        }
        return false;
    }

    private static String generateSHA256(String base) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(base.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
        for (byte b : encodedhash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String encryptAES(String data, String secretKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptAES(String encryptedData, String secretKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static String uploadToPinata(File file) throws Exception {
        OkHttpClient client = new OkHttpClient();
        RequestBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", file.getName(),
                        RequestBody.create(file, MediaType.parse("application/octet-stream")))
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

    private static boolean storeOnChain(String fileId, String ipfsCid, String dataHash, boolean isSensitive) {
        Web3j web3j = Web3j.build(new HttpService(ALCHEMY_RPC_URL));
        try {
            Credentials credentials = Credentials.create(PRIVATE_KEY);
            String dataTypeString = isSensitive ? "SENSITIVE_DATA" : "STANDARD_DATA";

            Function function = new Function(
                    "storeSensitiveData",
                    Arrays.asList(
                            new org.web3j.abi.datatypes.Utf8String(fileId), 
                            new org.web3j.abi.datatypes.Utf8String(ipfsCid), 
                            new org.web3j.abi.datatypes.Utf8String(dataHash), 
                            new org.web3j.abi.datatypes.Utf8String(dataTypeString)
                    ),
                    Collections.emptyList()
            );
            
            String encodedFunction = FunctionEncoder.encode(function);

            EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
                    credentials.getAddress(), DefaultBlockParameterName.PENDING).send();
            
            BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
            BigInteger gasLimit = BigInteger.valueOf(1000000); // Safe high limit for multi-string storage writes

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
                        System.out.println("Gas Used: " + receipt.getGasUsed());
                        return true;
                    } else {
                        System.out.println("[Transaction Reverted] EVM execution failed. Gas used: " + receipt.getGasUsed());
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
}