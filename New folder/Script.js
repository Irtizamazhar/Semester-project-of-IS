function previewImage(event) {
    const reader = new FileReader();
    reader.onload = function() {
        const output = document.getElementById('imagePreview');
        output.src = reader.result;
        output.style.display = 'block';
    };
    reader.readAsDataURL(event.target.files[0]);
}

async function encryptAndEncodeMessageAndImage() {
    const messageInput = document.getElementById('message').value;
    const passwordInput = document.getElementById('password').value;
    const imageInput = document.getElementById('image').files[0];

    if (!messageInput || !passwordInput || !imageInput) {
        document.getElementById('output').textContent = "Please provide a message, password, and image.";
        return;
    }

    const imageData = await readFileAsArrayBuffer(imageInput);
    const messageData = new TextEncoder().encode(messageInput);

    // Combine message and image data
    const combinedData = new Uint8Array(messageData.length + imageData.byteLength);
    combinedData.set(new Uint8Array(messageData), 0);
    combinedData.set(new Uint8Array(imageData), messageData.length);

    const encryptedData = await encryptAndEncode(combinedData, passwordInput);
    
    document.getElementById('output').textContent = "Encrypted and encoded data: " + arrayBufferToBase64(encryptedData);
}

async function decodeAndDecryptMessageAndImage() {
    const passwordInput = document.getElementById('password').value;
    const encodedData = prompt("Enter the encrypted and encoded data:");

    if (!encodedData || !passwordInput) {
        document.getElementById('output').textContent = "Please provide the encrypted data and password.";
        return;
    }

    const encryptedData = base64ToArrayBuffer(encodedData);
    const decryptedData = await decodeAndDecrypt(encryptedData, passwordInput);

    if (decryptedData) {
        // Find the separator (end of message data)
        let separatorIndex = decryptedData.findIndex((byte, index) => byte === 0);
        if (separatorIndex === -1) {
            separatorIndex = decryptedData.length;
        }
        
        const messageData = decryptedData.slice(0, separatorIndex);
        const imageData = decryptedData.slice(separatorIndex + 1);

        const message = new TextDecoder().decode(messageData);
        const imageBlob = new Blob([imageData], { type: 'image/png' });
        const imageUrl = URL.createObjectURL(imageBlob);

        document.getElementById('messageInput').innerHTML = `Decrypted message: ${message}<br><img src="${imageUrl}" alt="Decrypted Image">`;
    } else { 
        document.getElementById('output').textContent = "Decryption failed.";
    }
}

async function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsArrayBuffer(file);
    });
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

async function encryptAndEncode(data, password) {
    try {
        const keyDetails = await getKeyFromPassword(password);
        const key = keyDetails.key;
        const salt = keyDetails.salt;

        const iv = window.crypto.getRandomValues(new Uint8Array(16)); 

        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            data
        );

        const combined = new Uint8Array(salt.length + iv.length + new Uint8Array(encryptedData).length);
        combined.set(salt);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(encryptedData), salt.length + iv.length);

        return combined.buffer;
    } catch (error) {
        console.error("Encryption error:", error);
        return null;
    }
}
async function decodeAndDecryptMessageAndImage() {
    const passwordInput = document.getElementById('decryptPassword').value;
    const imageInput = document.getElementById('image').files[0];

    if (!passwordInput || !imageInput) {
        document.getElementById('output').textContent = "Please provide the encrypted image and password.";
        return;
    }

    try {
        const imageData = await readFileAsArrayBuffer(imageInput);
        const decryptedData = await decodeAndDecrypt(imageData, passwordInput);

        if (decryptedData) {
            // Find the separator (end of message data)
            let separatorIndex = decryptedData.findIndex((byte, index) => byte === 0);
            if (separatorIndex === -1) {
                separatorIndex = decryptedData.length;
            }
            
            const messageData = decryptedData.slice(0, separatorIndex);
            const imageData = decryptedData.slice(separatorIndex + 1);

            const message = new TextDecoder().decode(messageData);
            const imageBlob = new Blob([imageData], { type: 'image/png' });
            const imageUrl = URL.createObjectURL(imageBlob);

            // Display the decrypted message in the input field
            document.getElementById('messageInput').value = message;
            // Display the decrypted image in the output area
            document.getElementById('output').innerHTML = `Decrypted message: ${message}<br><img src="${imageUrl}" alt="Decrypted Image">`;
        } else {
            document.getElementById('output').textContent = "Decryption failed.";
        }
    } catch (error) {
        console.error("Error during decryption:", error);
        document.getElementById('output').textContent = "Decryption failed. See console for error details.";
    }
}


async function getKeyFromPassword(password, salt) {
    const encoder = new TextEncoder();
    const encodedPassword = encoder.encode(password);

    if (!salt) {
        salt = window.crypto.getRandomValues(new Uint8Array(8)); // Generate a random salt if not provided
    }

    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encodedPassword,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const iterations = 100000; 

    const key = await window.crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt,
            "iterations": iterations,
            "hash": "SHA-256"
        },
        keyMaterial,
        { "name": "AES-GCM", "length": 256 },
        true,
        ["encrypt", "decrypt"]
    );

    return { key, salt };
}
