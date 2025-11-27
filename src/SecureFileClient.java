import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public class SecureFileClient {

    // Même clé Base64 que le serveur (pré-partagée)
    private static final String AES_KEY_BASE64 = "ABEiM0RVZneImaq7zN3u/w==";

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        System.out.print("Adresse IP du serveur : ");
        String serverIp = scanner.nextLine();

        System.out.print("Port : ");
        int port = Integer.parseInt(scanner.nextLine());

        System.out.print("Login : ");
        String login = scanner.nextLine();

        System.out.print("Mot de passe : ");
        String password = scanner.nextLine();

        System.out.print("Chemin du fichier à envoyer : ");
        Path filePath = Path.of(scanner.nextLine());

        if (!Files.exists(filePath)) {
            System.err.println("Fichier introuvable: " + filePath);
            return;
        }

        try {
            byte[] fileBytes = Files.readAllBytes(filePath);
            String sha = CryptoUtils.sha256Hex(fileBytes);
            System.out.println("SHA-256 du fichier: " + sha);
            SecretKeySpec key = CryptoUtils.keyFromBase64(AES_KEY_BASE64);

            byte[] encrypted = CryptoUtils.encryptAES(fileBytes, key);
            System.out.println("Fichier chiffré: " + encrypted.length + " octets");

            try (Socket socket = new Socket(serverIp, port);
                 InputStream is = socket.getInputStream();
                 OutputStream os = socket.getOutputStream();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                 PrintWriter writer = new PrintWriter(new OutputStreamWriter(os, "UTF-8"), true);
                 DataOutputStream dataOut = new DataOutputStream(os)
            ) {
                // Phase 1 : Authentification
                String authLine = login + "|" + password;
                writer.println(authLine);
                String authResp = reader.readLine();
                if (authResp == null || !authResp.equals("AUTH_OK")) {
                    System.err.println("Authentification échouée: " + authResp);
                    return;
                }
                System.out.println("AUTH_OK reçu");

                // Phase 2 : metadata
                String meta = filePath.getFileName().toString() + "|" + fileBytes.length + "|" + sha;
                writer.println(meta);
                String ready = reader.readLine();
                if (ready == null || !ready.equals("READY_FOR_TRANSFER")) {
                    System.err.println("Server not ready: " + ready);
                    return;
                }
                System.out.println("READY_FOR_TRANSFER reçu");

                // Phase 3 : envoyer taille (int) puis octets chiffrés
                dataOut.writeInt(encrypted.length);
                dataOut.write(encrypted);
                dataOut.flush();
                System.out.println("Données envoyées.");

                // Lire la réponse finale
                String finalResp = reader.readLine();
                System.out.println("Réponse serveur: " + finalResp);

            } // socket auto-closé

        } catch (Exception e) {
            System.err.println("Erreur client: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
