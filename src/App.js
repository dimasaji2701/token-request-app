import React, { useState, useEffect } from "react";
import "./App.css";

const App = () => {
  const [corpId, setCorpId] = useState("");
  const [userId, setUserId] = useState("");
  const [responseData, setResponseData] = useState(null);
  const [decryptedHmacKey, setDecryptedHmacKey] = useState(null); // Untuk menyimpan hasil dekripsi
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Pastikan file e2ee.js sudah dimuat
    const script = document.createElement("script");
    script.src = "/e2ee.js"; // Memuat e2ee.js dari folder public
    script.async = true;
    script.onload = () => {
      console.log("e2ee.js loaded successfully!");
    };
    script.onerror = () => {
      console.error("Failed to load e2ee.js");
    };
    document.body.appendChild(script);

    return () => {
      // Bersihkan script setelah komponen di-unmount
      document.body.removeChild(script);
    };
  }, []);

  const handleSubmit = async () => {
    if (!corpId || !userId) {
      alert("Please fill in both CorpId and UserId.");
      return;
    }

    setLoading(true);

    try {
      // Generate sessionKey dan encrypt menggunakan createKey dan encryptKey dari e2ee.js
      const sessionKey = await window.createKey();
      const publicKey =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxRjSBw0jCl+3Cxnr+TgWel/HldUaDQqjl8Ogukho3KF6E/3IQrIy5FhEECuNiUMECFVKuGQHRuS5UnL4nwYsMh3tmvBWajG22lrCwRlSjxITR7/pQIxpVhC/hukIBtKN6qZxjAbW6VWAioxpWQFplWmc8uUVrOrO5LggfqSE9XIqMi3NwzyHvfaGF6CFsMNsbhwT4ipbbVwP8C2H3vVvlLHbNhA+iZ1lufC0YTpB9OQHrkYAEb/aKUmvhNIqFfZUuckHV1T+XCuPddU9XyjyD3EbwcrsWIDlpgcI6Z8QvFX8Yx9vtGhwPQbsx23l91wFm/HcIkkQyfQiZfa86+ZqowIDAQAB"; // Contoh public key
      const encSessionKey = await window.encryptKey(publicKey, sessionKey);
      const keyName = corpId+userId
      const encKeyName = await window.encryptData(sessionKey, keyName)
      const body = JSON.stringify({ encKeyName});

      console.log("hasil encrypt kombinasinya: " + await window.encryptData(sessionKey, encKeyName))

      const response = await fetch("http://localhost:8080/api/v1/token/key", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "encSessionKey":encSessionKey
        },
        body,
      });

      if (!response.ok) {
        throw new Error("Network response was not ok");
      }

      const data = await response.json();
      setResponseData(data);

      // Dekripsi encHmacKey setelah mendapat response
      if (data && data.encHmacKey) {
        const decrypted = window.decryptData(sessionKey, data.encHmacKey); // Memanggil decryptData untuk mendekripsi
        setDecryptedHmacKey(decrypted); // Menyimpan hasil dekripsi
      }
    } catch (error) {
      console.error("Error:", error);
      setResponseData({ error: error.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>React App - Token Key Request</h1>
      <div className="form-container">
        <label htmlFor="corpId">Corp ID:</label>
        <input
          type="text"
          id="corpId"
          value={corpId}
          onChange={(e) => setCorpId(e.target.value)}
          placeholder="Enter Corp ID"
        />
        <label htmlFor="userId">User ID:</label>
        <input
          type="text"
          id="userId"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          placeholder="Enter User ID"
        />
        <button onClick={handleSubmit} disabled={loading}>
          {loading ? "Loading..." : "Submit"}
        </button>
      </div>

      {responseData && (
        <div className="response-container">
          <h2>Response:</h2>
          <pre>{JSON.stringify(responseData, null, 2)}</pre>
        </div>
      )}

      {decryptedHmacKey && (
        <div className="response-container">
          <h2>Decrypted HMAC Key:</h2>
          <pre>{decryptedHmacKey}</pre>
        </div>
      )}
    </div>
  );
};

export default App;
