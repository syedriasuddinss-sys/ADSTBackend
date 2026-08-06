
public class retrieveAndVerifyData implements ADSTBackend{ 
	public static void retrieveAndVerifyData(String fileId) {
        System.out.println("\n[Retriever] Initiating secure retrieval for File ID: " + fileId);
        Web3j web3j = Web3j.build(new HttpService(ALCHEMY_RPC_URL));
        
        try {
            // 1. Query the Smart Contract for metadata (IPFS CID and Data Hash)
            Function function = new Function(
                    "getSensitiveData",
                    Arrays.asList(new Utf8String(fileId)),
                    Arrays.asList(
                            new org.web3j.abi.datatypes.Utf8String(),
                            new org.web3j.abi.datatypes.Utf8String(),
                            new org.web3j.abi.datatypes.Utf8String(),
                            new org.web3j.abi.datatypes.generated.Uint256()
                    )
            );

            String encodedFunction = FunctionEncoder.encode(function);
            org.web3j.protocol.core.methods.response.EthCall response = web3j.ethCall(
                    org.web3j.protocol.core.methods.request.Transaction.createEthCallTransaction(
                            null, CONTRACT_ADDRESS, encodedFunction),
                    DefaultBlockParameterName.LATEST).send();

            List<org.web3j.abi.datatypes.Type> result = org.web3j.abi.FunctionReturnDecoder.decode(
                    response.getValue(), function.getOutputParameters());

            if (result.isEmpty()) {
                System.out.println("[Retriever Error]: File ID not found on-chain.");
                return;
            }

            String ipfsCid = result.get(0).getValue().toString();
            String onChainHash = result.get(1).getValue().toString();
            String dataType = result.get(2).getValue().toString();

            System.out.println("[Retriever] On-chain record found.");
            System.out.println(" -> IPFS CID: " + ipfsCid);
            System.out.println(" -> Expected Hash: " + onChainHash);
            System.out.println(" -> Data Classification: " + dataType);

            // 2. Download the encrypted payload from Pinata IPFS Gateway
            System.out.println("[Retriever] Downloading encrypted payload from IPFS gateway...");
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://gateway.pinata.cloud/ipfs/" + ipfsCid)
                    .build();

            String encryptedPayload;
            try (Response ipfsResponse = client.newCall(request).execute()) {
                if (!ipfsResponse.isSuccessful()) throw new RuntimeException("IPFS Download Failed: " + ipfsResponse);
                encryptedPayload = ipfsResponse.body().string();
            }

            // 3. Decrypt the payload using AES_SECRET_KEY
            System.out.println("[Retriever] Decrypting payload using local AES key...");
            String decryptedPayload = decryptAES(encryptedPayload, AES_SECRET_KEY);
            System.out.println(" -> Decrypted Content: " + decryptedPayload);

            // 4. Verify Integrity (Hash Check)
            System.out.println("[Retriever] Verifying local cryptographic hash against blockchain...");
            // Note: For sensitive data, we hash the decrypted plaintext to match original generation
            String currentHash = generateSHA256(decryptedPayload);

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

    private static String decryptAES(String encryptedData, String secretKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
	
	

}
