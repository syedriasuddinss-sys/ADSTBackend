import okhttp3.*;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
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
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class ADSTBackend {
    private static final String PINATA_JWT = System.getenv("PINATA_JWT") != null ? System.getenv("PINATA_JWT") : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiI1MTkzYjhkNi04MjFkLTQ1MTktYTNiMi0xNWE3NWNjZDcwYjAiLCJlbWFpbCI6InN5ZWRyaWFzdWRkaW4ucy5zQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJwaW5fcG9saWN5Ijp7InJlZ2lvbnMiOlt7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6IkZSQTEifSx7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6Ik5ZQzEifV0sInZlcnNpb24iOjF9LCJtZmFfZW5hYmxlZCI6ZmFsc2UsInN0YXR1cyI6IkFDVElWRSJ9LCJhdXRoZW50aWNhdGlvblR5cGUiOiJzY29wZWRLZXkiLCJzY29wZWRLZXlLZXkiOiI0YmNiNzU4YzRmOWIxNDg4YjVmMSIsInNjb3BlZEtleVNlY3JldCI6IjJkNzk3MGE2MWY1NjExZWY0NjQ1ZTI1ZDY1N2E5ZWIxZWVhNTllOGI3MzFjOTJjYTg0YjdjNjBiZmU0OTBiYTkiLCJleHAiOjE4MTc0NTcxNDd9.lCRC7g8sfBd9KsfIVYeB3vJ6Dxw_Cph8iD00UJS5knk";
    
    // Verified 20-byte Ethereum address format (0x + 40 hex characters)
    private static final String CONTRACT_ADDRESS = "0xD7ACd2a9FD159E69Bb102A1ca21C9a3e3A5F771B";
    
    private static final String PRIVATE_KEY = System.getenv("SEPOLIA_PRIVATE_KEY") != null ? System.getenv("SEPOLIA_PRIVATE_KEY") : "38cea97b600035168a73d8ba391285de33cfd827b158334503df33c4d93c6b13";
    private static final String ALCHEMY_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com";
    
    private static final String AES_SECRET_KEY = "SecureVaultKey16"; 

    public static void main(String[] args) {
        try {
            System.out.println("Initiating Decentralized Sensitive Data Vault Protocol...");

            String sensitivePayload = "Username: sys_admin | PasswordHash: 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 | Role: Root_Access | AccessTime: 2026-06-05";
            
            String dataHash = generateSHA256(sensitivePayload);
            System.out.println("Generated Local Data Hash: " + dataHash);

            String encryptedPayload = encryptAES(sensitivePayload, AES_SECRET_KEY);

            File secureFile = new File("user_credentials_vault.dat");
            Files.writeString(secureFile.toPath(), encryptedPayload, StandardCharsets.UTF_8);

            String ipfsCid = uploadToPinata(secureFile);
            System.out.println("Successfully secured & pinned to IPFS. CID: " + ipfsCid);

            // Generate a unique record ID per run to completely avoid storage collision/caching bugs
            String targetRecordId = "CRED-LOG-" + System.currentTimeMillis();
            
            // Broadcast and poll for explicit on-chain execution success receipt
            boolean isMinedSuccessfully = writeAndVerifyTransactionOnChain(targetRecordId, ipfsCid, dataHash, "USER_CREDENTIALS");

            if (isMinedSuccessfully) {
                verifySensitiveDataFromBlockchain(targetRecordId, AES_SECRET_KEY);
            } else {
                System.out.println("[Execution Aborted]: Transaction reverted or failed to confirm on-chain.");
            }

            if (secureFile.exists()) secureFile.delete();

        } catch (Exception e) {
            System.out.println("[Main Execution Status]: " + e.getMessage());
        }
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
        return new String(cipher.doFinal(decodedBytes), StandardCharsets.UTF_8);
    }

    private static String uploadToPinata(File file) throws Exception {
        System.out.println("Routing encrypted data packet to Pinata IPFS Gateway...");
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
            String responseBody = response.body().string();
            return responseBody.split("\"IpfsHash\":\"")[1].split("\"")[0];
        }
    }

    private static boolean writeAndVerifyTransactionOnChain(String recordId, String ipfsCid, String dataHash, String dataType) {
        Web3j web3j = Web3j.build(new HttpService(ALCHEMY_RPC_URL));
        try {
            System.out.println("Building blockchain transaction for SensitiveVault contract...");
            Credentials credentials = Credentials.create(PRIVATE_KEY);

            Function function = new Function(
                    "storeSensitiveData",
                    Arrays.asList(
                            new Utf8String(recordId), 
                            new Utf8String(ipfsCid), 
                            new Utf8String(dataHash), 
                            new Utf8String(dataType)
                    ),
                    Collections.emptyList()
            );
            String encodedFunction = FunctionEncoder.encode(function);

            EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
                    credentials.getAddress(), DefaultBlockParameterName.PENDING).send();
            BigInteger nonce = ethGetTransactionCount.getTransactionCount();

            // Bumped gas limit to 500,000 to completely prevent out-of-gas reverts on dynamic string storage
            BigInteger gasLimit = BigInteger.valueOf(500000);
            BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();

            RawTransaction rawTransaction = RawTransaction.createTransaction(
                    nonce, gasPrice, gasLimit, CONTRACT_ADDRESS, encodedFunction);
            
            long chainId = 11155111; 
            byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, chainId, credentials);
            String hexValue = Numeric.toHexString(signedMessage);

            System.out.println("Executing Sepolia Network Secure Broadcast...");
            EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

            if (ethSendTransaction.hasError()) {
                System.out.println("[Blockchain Broadcast Error]: " + ethSendTransaction.getError().getMessage());
                return false;
            }

            String txHash = ethSendTransaction.getTransactionHash();
            System.out.println("Broadcast successful. Transaction Hash: " + txHash);
            System.out.println("Polling Sepolia network for confirmed transaction receipt...");

            // Polling loop to dynamically check the block receipt instead of blind sleeping
            int maxRetries = 30;
            int attempt = 0;
            while (attempt < maxRetries) {
                EthGetTransactionReceipt receiptResponse = web3j.ethGetTransactionReceipt(txHash).send();
                Optional<TransactionReceipt> receiptOpt = receiptResponse.getTransactionReceipt();

                if (receiptOpt.isPresent()) {
                    TransactionReceipt receipt = receiptOpt.get();
                    String status = receipt.getStatus();
                    System.out.println("Transaction mined! Status code: " + status);

                    // "0x1" indicates success, "0x0" indicates an EVM revert
                    if ("0x1".equalsIgnoreCase(status)) {
                        System.out.println("SUCCESS! Sensitive record cryptographically anchored and verified on-chain.");
                        return true;
                    } else {
                        System.out.println("[Transaction Reverted]: EVM execution failed on-chain (Out of gas or contract require failure).");
                        return false;
                    }
                }

                attempt++;
                Thread.sleep(3000); // Poll every 3 seconds
            }

            System.out.println("[Timeout]: Transaction receipt was not mined within the polling window.");
            return false;

        } catch (Exception e) {
            System.out.println("[Transaction Status Exception]: " + e.getMessage());
            return false;
        } finally {
            web3j.shutdown();
        }
    }

    private static void verifySensitiveDataFromBlockchain(String recordId, String secretKey) {
        Web3j web3j = Web3j.build(new HttpService(ALCHEMY_RPC_URL));
        try {
            System.out.println("\nQuerying Vault Contract for Record ID: " + recordId);

            Function function = new Function(
                    "getSensitiveData", 
                    Arrays.asList(new Utf8String(recordId)),
                    Arrays.asList(
                            new TypeReference<Utf8String>() {}, 
                            new TypeReference<Utf8String>() {}, 
                            new TypeReference<Utf8String>() {}, 
                            new TypeReference<Uint256>() {}     
                    )
            );

            String encodedFunction = FunctionEncoder.encode(function);
            
            org.web3j.protocol.core.methods.response.EthCall response = web3j.ethCall(
                    org.web3j.protocol.core.methods.request.Transaction.createEthCallTransaction(
                            null, CONTRACT_ADDRESS, encodedFunction),
                    DefaultBlockParameterName.LATEST
            ).send();

            String rawHexValue = response.getValue();
            System.out.println("Vault Verification Response Retrieved.");

            List<Type> decodedResponse = org.web3j.abi.FunctionReturnDecoder.decode(rawHexValue, function.getOutputParameters());

            if (!decodedResponse.isEmpty() && decodedResponse.get(0).getValue() != null && !decodedResponse.get(0).getValue().toString().isEmpty()) {
                String fetchedCid = decodedResponse.get(0).getValue().toString();
                System.out.println("----------------------------------------");
                System.out.println("IPFS CID     : " + fetchedCid);
                System.out.println("Data Hash    : " + decodedResponse.get(1).getValue());
                System.out.println("Data Type    : " + decodedResponse.get(2).getValue());
                System.out.println("Timestamp    : " + decodedResponse.get(3).getValue());
                
                OkHttpClient client = new OkHttpClient();
                Request request = new Request.Builder().url("https://gateway.pinata.cloud/ipfs/" + fetchedCid).build();
                try (Response ipfsResponse = client.newCall(request).execute()) {
                    if (ipfsResponse.isSuccessful() && ipfsResponse.body() != null) {
                        String encryptedPayloadFromIpfs = ipfsResponse.body().string();
                        String decryptedPayload = decryptAES(encryptedPayloadFromIpfs, secretKey);
                        System.out.println("Decrypted Payload: " + decryptedPayload);
                    }
                }
                System.out.println("----------------------------------------");
            } else {
                System.out.println("No record found or data is empty on-chain.");
            }

        } catch (Exception e) {
            System.out.println("[Verification Status]: " + e.getMessage());
        } finally {
            web3j.shutdown();
        }
    }
}