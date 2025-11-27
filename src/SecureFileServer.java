import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class SecureFileServer {

    // Clé AES (Base64) partagée — même valeur côté client
    // Exemple (16 bytes key): 00112233445566778899aabbccddeeff -> Base64 = ABEiM0RVZneImaq7zN3u/w==
    private static final String AES_KEY_BASE64 = "ABEiM0RVZneImaq7zN3u/w==";

    // Identifiants valides (exemple simple)
    private static final Map<String, String> credentials = new HashMap<>();

    static {
        credentials.put("alice", "password123");
        credentials.put("bob", "secret");
    }

    public static void main(String[] args) {
        int port = 5000;
        if (args.length >= 1) {
            try { port = Integer.parseInt(args[0]); } catch (NumberFormatException ignored) {}
        }

        // Crée le dossier de réception si n'existe pas
        try {
            Files.createDirectories(Path.of("received"));
        } catch (IOException e) {
            System.err.println("Impossible de créer le dossier received/: " + e.getMessage());
            return;
        }

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("SecureFileServer démarré sur le port " + port);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Nouvelle connexion depuis " + clientSocket.getRemoteSocketAddress());
                new Thread(new ClientTransferHandler(clientSocket, AES_KEY_BASE64)).start();
            }
        } catch (IOException e) {
            System.err.println("Erreur du serveur : " + e.getMessage());
        }
    }

    // Handler pour chaque client
    private static class ClientTransferHandler implements Runnable {
        private final Socket socket;
        private final SecretKeySpec aesKey;

        public ClientTransferHandler(Socket socket, String aesKeyBase64) {
            this.socket = socket;
            this.aesKey = CryptoUtils.keyFromBase64(aesKeyBase64);
        }

        @Override
        public void run() {
            try (
                    InputStream is = socket.getInputStream();
                    OutputStream os = socket.getOutputStream();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                    PrintWriter writer = new PrintWriter(new OutputStreamWriter(os, "UTF-8"), true);
                    DataInputStream dataIn = new DataInputStream(is)
            ) {
                // Phase 1 : Authentification
                String authLine = reader.readLine(); // attend login|password
                if (authLine == null) {
                    closeSocket();
                    return;
                }
                String[] authParts = authLine.split("\\|", 2);
                if (authParts.length != 2) {
                    writer.println("AUTH_FAIL");
                    closeSocket();
                    return;
                }
                String login = authParts[0];
                String password = authParts[1];
                System.out.println("Tentative d'auth: " + login);

                if (!credentials.containsKey(login) || !credentials.get(login).equals(password)) {
                    writer.println("AUTH_FAIL");
                    System.out.println("AUTH_FAIL pour " + login);
                    closeSocket();
                    return;
                }
                writer.println("AUTH_OK");
                System.out.println("AUTH_OK pour " + login);

                // Phase 2 : Négociation (metadata)
                String metaLine = reader.readLine(); // attente filename|origSize|sha256hex
                if (metaLine == null) {
                    closeSocket();
                    return;
                }
                String[] meta = metaLine.split("\\|", 3);
                if (meta.length != 3) {
                    writer.println("TRANSFER_FAIL");
                    closeSocket();
                    return;
                }
                String filename = Path.of(meta[0]).getFileName().toString(); // sécuriser le nom
                long origSize;
                try {
                    origSize = Long.parseLong(meta[1]);
                } catch (NumberFormatException e) {
                    writer.println("TRANSFER_FAIL");
                    closeSocket();
                    return;
                }
                String expectedSha = meta[2];

                System.out.println(String.format("Reçu metadata: %s | %d bytes | sha=%s", filename, origSize, expectedSha));
                writer.println("READY_FOR_TRANSFER");

                // Phase 3 : Transfert
                // On s'attend à recevoir d'abord un int (taille des octets chiffrés), puis les octets
                int encLen;
                try {
                    encLen = dataIn.readInt();
                } catch (EOFException eof) {
                    System.out.println("Client a fermé la connexion avant d'envoyer les données.");
                    closeSocket();
                    return;
                }

                if (encLen <= 0) {
                    writer.println("TRANSFER_FAIL");
                    closeSocket();
                    return;
                }

                byte[] encBytes = new byte[encLen];
                dataIn.readFully(encBytes); // lit l'intégralité

                System.out.println("Reçu " + encLen + " octets chiffrés. Déchiffrement...");

                byte[] plain;
                try {
                    plain = CryptoUtils.decryptAES(encBytes, aesKey);
                } catch (Exception ex) {
                    System.err.println("Erreur durant le déchiffrement: " + ex.getMessage());
                    writer.println("TRANSFER_FAIL");
                    closeSocket();
                    return;
                }

                // Enregistre le fichier dans received/
                Path outPath = Path.of("received", filename);
                Files.write(outPath, plain);
                System.out.println("Fichier sauvegardé dans " + outPath.toString());

                // Vérifie l'intégrité SHA-256
                String actualSha = CryptoUtils.sha256Hex(plain);
                if (actualSha.equalsIgnoreCase(expectedSha)) {
                    writer.println("TRANSFER_SUCCESS");
                    System.out.println("Hash ok -> TRANSFER_SUCCESS");
                } else {
                    writer.println("TRANSFER_FAIL");
                    System.out.println("Hash mismatch -> TRANSFER_FAIL");
                }

            } catch (IOException e) {
                System.err.println("IO exception dans le handler: " + e.getMessage());
            } catch (Exception e) {
                System.err.println("Erreur inattendue: " + e.getMessage());
            } finally {
                closeSocket();
            }
        }

        private void closeSocket() {
            try {
                if (!socket.isClosed()) socket.close();
            } catch (IOException ignored) {}
        }
    }
}
