package com.adst.backend;
import okhttp3.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.web3j.abi.FunctionEncoder;
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
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;

@SpringBootApplication
@RestController
@RequestMapping("/api/adst")
public class ADSTApplication {

    private static final String PINATA_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiI1MTkzYjhkNi04MjFkLTQ1MTktYTNiMi0xNWE3NWNjZDcwYjAiLCJlbWFpbCI6InN5ZWRyaWFzdWRkaW4ucy5zQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJwaW5fcG9saWN5Ijp7InJlZ2lvbnMiOlt7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6IkZSQTEifSx7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6Ik5ZQzEifV0sInZlcnNpb24iOjF9LCJtZmFfZW5hYmxlZCI6ZmFsc2UsInN0YXR1cyI6IkFDVElWRSJ9LCJhdXRoZW50aWNhdGlvblR5cGUiOiJzY29wZWRLZXkiLCJzY29wZWRLZXlLZXkiOiI0YmNiNzU4YzRmOWIxNDg4YjVmMSIsInNjb3BlZEtleVNlY3JldCI6IjJkNzk3MGE2MWY1NjExZWY0NjQ1ZTI1ZDY1N2E5ZWIxZWVhNTllOGI3MzFjOTJjYTg0YjdjNjBiZmU0OTBiYTkiLCJleHAiOjE4MTc0NTcxNDd9.lCRC7g8sfBd9KsfIVYeB3vJ6Dxw_Cph8iD00UJS5knk"; 
    private static final String CONTRACT_ADDRESS = "0xdb1aa79410de2a671e31b640b5bad6d19166ff61"; 
    private static final String PRIVATE_KEY = "38cea97b600035168a73d8ba391285de33cfd827b158334503df33c4d93c6b13"; 
    private static final String ALCHEMY_RPC_URL = "https://eth-sepolia.g.alchemy.com/v2/alch_Fth6V0gMIuxHClEO9CoUv";
    private static final String AES_SECRET_KEY = "1234567890123456"; 

    private static final String[] SENSITIVE_PATTERNS = {
        "\\b(?:\\d[ -]*?){13,16}\\b",
        "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
        "(?i)(password|passwd|private_key|api_key|secret).{0,10}[:=].{1,50}"
    };

    public static void main(String[] args) {
        SpringApplication.run(ADSTApplication.class, args);
    }

    @PostMapping("/process")
    public Map<String, Object> processPayload(@org.springframework.web.bind.annotation.RequestBody Map<String, String> requestBody) {
        Map<String, Object> response = new HashMap<>();
        try {
            String payload = requestBody.get("payload");
            if (payload == null || payload.isEmpty()) {
                response.put("error", "Payload is missing or empty.");
                return response;
            }

            String fileId = "ADST-" + UUID.randomUUID().toString();
            boolean isSensitive = classifyData(payload);
            String encryptedPayload = encryptAES(payload, AES_SECRET_KEY);
            String dataHash = generateSHA256(payload);

            if (isSensitive) {
                File tempFile = new File("temp_ipfs.dat");
                Files.writeString(tempFile.toPath(), encryptedPayload, StandardCharsets.UTF_8);
                String ipfsCid = uploadToPinata(tempFile);
                storeOnChain(fileId, ipfsCid, dataHash);
                Files.deleteIfExists(tempFile.toPath());
                response.put("routingPath", "SENSITIVE (Blockchain & IPFS)");
                response.put("ipfsCid", ipfsCid);
            } else {
                saveToLocalFolder(fileId, encryptedPayload);
                response.put("routingPath", "STANDARD (Local Storage)");
            }

            response.put("fileId", fileId);
            response.put("status", "SUCCESS");

        } catch (Exception e) {
            response.put("status", "FAILED");
            response.put("error", e.getMessage());
        }
        return response;
    }

    @GetMapping("/retrieve/{fileId}")
    public Map<String, Object> retrieveFile(@PathVariable String fileId) {
        Map<String, Object> response = new HashMap<>();
        try {
            String filePath = "Standard_Storage_Local/" + fileId + ".dat";
            File file = new File(filePath);

            if (!file.exists()) {
                response.put("status", "FAILED");
                response.put("error", "File ID not found in local storage.");
                return response;
            }

            String encryptedData = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            String decryptedPayload = decryptAES(encryptedData, AES_SECRET_KEY);

            response.put("status", "SUCCESS");
            response.put("fileId", fileId);
            response.put("decryptedContent", decryptedPayload);

        } catch (Exception e) {
            response.put("status", "FAILED");
            response.put("error", e.getMessage());
        }
        return response;
    }

    private static boolean classifyData(String data) {
        for (String regex : SENSITIVE_PATTERNS) {
            if (java.util.regex.Pattern.compile(regex).matcher(data).find()) return true;
        }
        return false;
    }

    private static String encryptAES(String data, String secretKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private static String decryptAES(String encryptedData, String secretKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedBytes), StandardCharsets.UTF_8);
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

    private static void saveToLocalFolder(String fileId, String encryptedData) throws Exception {
        File directory = new File("Standard_Storage_Local");
        if (!directory.exists()) directory.mkdir();
        Files.writeString(Paths.get(directory.getPath() + "/" + fileId + ".dat"), encryptedData, StandardCharsets.UTF_8);
    }

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

    private static boolean storeOnChain(String fileId, String ipfsCid, String dataHash) {
        Web3j web3j = Web3j.build(new HttpService(ALCHEMY_RPC_URL));
        try {
            Credentials credentials = Credentials.create(PRIVATE_KEY);
            Function function = new Function(
                    "storeSensitiveData",
                    Arrays.asList(new Utf8String(fileId), new Utf8String(ipfsCid), new Utf8String(dataHash), new Utf8String("SENSITIVE_DATA")),
                    Collections.emptyList()
            );
            String encodedFunction = FunctionEncoder.encode(function);
            EthGetTransactionCount count = web3j.ethGetTransactionCount(credentials.getAddress(), DefaultBlockParameterName.PENDING).send();
            BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
            
            RawTransaction rawTx = RawTransaction.createTransaction(count.getTransactionCount(), gasPrice, BigInteger.valueOf(1000000), CONTRACT_ADDRESS, encodedFunction);
            byte[] signed = TransactionEncoder.signMessage(rawTx, 11155111, credentials);
            EthSendTransaction sentTx = web3j.ethSendRawTransaction(Numeric.toHexString(signed)).send();
            
            if (sentTx.hasError()) return false;
            String txHash = sentTx.getTransactionHash();

            int attempt = 0;
            while (attempt < 30) {
                Optional<TransactionReceipt> receipt = web3j.ethGetTransactionReceipt(txHash).send().getTransactionReceipt();
                if (receipt.isPresent() && "0x1".equalsIgnoreCase(receipt.get().getStatus())) return true;
                attempt++;
                Thread.sleep(3000);
            }
        } catch (Exception e) {
            return false;
        } finally {
            web3j.shutdown();
        }
        return false;
    }
}