// Flag to track if the user uploaded a file
let isFileUpload = false;
// Stores the content of the uploaded file
let uploadedFileContent = "";

// Shortcut for getting an element by ID
const $ = (id) => document.getElementById(id);

// DOM Elements
const messageBox = $("message");
const uploadIconBtn = $("uploadIcon");
const deleteIconBtn = $("deleteIcon");
const keyIconBtn = $("keyIcon");
const pasteIconBtn = $("pasteIcon");
const extraField = $("extraParam");
const extraLabel = $("extraLabel");
const extraError = $("extraErr");
const generatedExtraBox = $("generatedExtra");
const extraOutput = $("extraOutput");
const clearMsgIconBtn = $("clearMsgIcon");
const clearKeyIconBtn = $("clearKeyIcon");
const clearExtraIconBtn = $("clearExtraIcon");
const pasteExtraIconBtn = $("pasteExtraIcon");
const pasteKeyIconBtn = $("pasteKeyIcon");
const extraWrapper = $("extraWrapper");

// Base API URL
const API = window.location.origin;

// Helper to check if a string is valid hex
const isHex = (str) => /^[0-9a-fA-F]+$/.test(str);

// Clear form validation error messages
const clearErrors = () => {
    $("msgErr").textContent = "";
    $("keyErr").textContent = "";
};

// Event Listeners
$("mode").addEventListener("change", updateExtraFieldVisibility);
$("operation").addEventListener("change", updateExtraFieldVisibility);
document.addEventListener("DOMContentLoaded", () => {
    updateExtraFieldVisibility();
    toggleClearMsgIcon();
    toggleClearKeyIcon();
    toggleClearExtraIcon();
});

// Show/hide clear icons based on current field state
function toggleClearMsgIcon() {
    clearMsgIconBtn.style.display = isFileUpload ? "none" : "inline";
}
function toggleClearKeyIcon() {
    clearKeyIconBtn.style.display = "inline";
}
function toggleClearExtraIcon() {
    clearExtraIconBtn.style.display = extraField.disabled ? "none" : "inline";
}

// Show or hide the "extra" field (IV/nonce/counter) depending on mode and operation
function updateExtraFieldVisibility() {
    const mode = $("mode").value;
    const op = $("operation").value;
    const show = op === "decrypt" && mode !== "ECB";
    extraWrapper.style.display =
        extraField.style.display =
        extraLabel.style.display =
        show ? "block" : "none";
    extraField.disabled = !show;
    if (!show) {
        extraField.value = "";
        extraError.textContent = "";
    }
    toggleClearExtraIcon();
}

// Create hidden file input for uploading files
const fileInput = document.createElement("input");
fileInput.type = "file";
fileInput.accept = ".txt,.bin";
fileInput.style.display = "none";
document.body.appendChild(fileInput);

// UI for showing file upload icons
function showUploadIcon() {
    uploadIconBtn.style.display = "inline";
    deleteIconBtn.style.display = "none";
    pasteIconBtn.style.display = "inline";
    toggleClearMsgIcon();
}

// UI for showing delete icon after file uploaded
function showDeleteIcon() {
    uploadIconBtn.style.display =
        pasteIconBtn.style.display =
        clearMsgIconBtn.style.display =
        "none";
    deleteIconBtn.style.display = "inline";
}

// When clicking upload icon, trigger hidden file input
uploadIconBtn.addEventListener("click", () => fileInput.click());

// Clicking message box while file is uploaded allows re-upload
messageBox.addEventListener("click", () => {
    if (isFileUpload) fileInput.click();
    toggleClearMsgIcon();
});

// Read file contents when user selects a file
fileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
        const plain = new TextDecoder().decode(new Uint8Array(reader.result));
        uploadedFileContent = plain;
        isFileUpload = true;
        messageBox.value = `${file.name} uploaded`;
        messageBox.readOnly = true;
        messageBox.classList.add("file-loaded");
        showDeleteIcon();
    };
    reader.readAsArrayBuffer(file);
});

// Allow deleting uploaded file and restoring normal input
deleteIconBtn.addEventListener("click", () => {
    isFileUpload = false;
    uploadedFileContent = "";
    messageBox.value = "";
    messageBox.readOnly = false;
    fileInput.value = "";
    messageBox.classList.remove("file-loaded");
    showUploadIcon();
});

// User typing in message box after file upload clears upload state
messageBox.addEventListener("input", () => {
    if (isFileUpload) {
        isFileUpload = false;
        uploadedFileContent = "";
        messageBox.readOnly = false;
        messageBox.classList.remove("file-loaded");
        showUploadIcon();
    }
    toggleClearMsgIcon();
});

// Paste clipboard content into the message box
pasteIconBtn.addEventListener("click", async () => {
    try {
        const text = await navigator.clipboard.readText();
        if (text) {
            messageBox.value = text;
            isFileUpload = false;
            uploadedFileContent = "";
            messageBox.readOnly = false;
            messageBox.classList.remove("file-loaded");
            showUploadIcon();
            toggleClearMsgIcon();
        }
    } catch { }
});

// Paste clipboard content into the hex key field
pasteKeyIconBtn.addEventListener("click", async () => {
    try {
        const txt = await navigator.clipboard.readText();
        if (txt) $("hexKey").value = txt;
    } catch {}
});

// Auto toggle clear icons based on input changes
$("hexKey").addEventListener("input", toggleClearKeyIcon);
extraField.addEventListener("input", toggleClearExtraIcon);

// Paste clipboard content into the extra field (IV/nonce)
pasteExtraIconBtn.addEventListener("click", async () => {
    try {
        const text = await navigator.clipboard.readText();
        if (text) {
            extraField.value = text;
            toggleClearExtraIcon();
        }
    } catch { }
});

// Clear buttons for message, key, and extra fields
clearMsgIconBtn.addEventListener("click", () => {
    messageBox.value = "";
});
clearKeyIconBtn.addEventListener("click", () => {
    $("hexKey").value = "";
});
clearExtraIconBtn.addEventListener("click", () => {
    extraField.value = "";
});

// Fetch wrapper for API calls
async function fetchDES(endpoint, payload) {
    const r = await fetch(`${API}/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        credentials: "include",
    });
    return r.json();
}

// Update result output
const writeResult = (txt) => ($("result").textContent = txt);

// Helper to render rounds or keys nicely
const renderList = (id, title, items, cls) => {
    const box = $(id);
    box.innerHTML = items.length ? `<h4>${title}</h4>` : "";
    items.forEach((item, i) => {
        let v = item;
        if (i === 0 && typeof item === "object" && item) {
            v = item["Combined (pre-swap)"] || JSON.stringify(item);
            if (/^[01]+$/.test(v)) v = parseInt(v, 2).toString(16).toLowerCase();
        }
        box.innerHTML += `<div class="${cls}">Round ${i + 1}: ${v}</div>`;
    });
};

// Handle form submission
function handleSubmit() {
    $("operation").value === "encrypt" ? handleEncrypt() : handleDecrypt();
}

// Disable or enable submit button
const disableButtons = (s) => ($("submitBtn").disabled = s);

// Encrypt flow
async function handleEncrypt() {
    clearErrors();
    updateExtraFieldVisibility();
    const message = isFileUpload ? uploadedFileContent : messageBox.value.trim();
    const key = $("hexKey").value.trim().toLowerCase();
    const mode = $("mode").value;

    // Input validations
    if (!message) {
        $("msgErr").textContent = "Message required";
        return;
    }
    if (!isHex(key) || key.length !== 16) {
        $("keyErr").textContent = "Key must be 16-char hex";
        return;
    }

    disableButtons(true);
    try {
        const res = await fetchDES("encrypt", { message, hex_key: key, mode });

        const hex = res.encrypted_hex || "";

        // Display encrypted text
        const writeResult = (txt) => ($("result").innerHTML = `<pre>${txt}</pre>`);
        writeResult(`Encrypted (hex):\n${res.encrypted_hex}`);
        
        // Download if file was uploaded
        if (isFileUpload)
            downloadTextFile(res.encrypted_hex, `encrypted_${Date.now()}.txt`);

        // Show extra field if available
        if (res.extra) {
            generatedExtraBox.style.display = "block";
            extraOutput.textContent = res.extra;
        } else {
            generatedExtraBox.style.display = "none";
            extraOutput.textContent = "";
        }

        // Show rounds and keys
        renderList("roundBox", "Round Results", res.round_results, "round");
        renderList("keyBox", "Key Expansions", res.key_expansions, "key");
    } catch (e) {
        writeResult(`Error: ${e.message}`);
        renderList("roundBox", "", [], "round");
        renderList("keyBox", "", [], "key");
    } finally {
        disableButtons(false);
    }
    $("viewDetailsBtn").style.display = "block";
}

// Decrypt flow
async function handleDecrypt() {
    clearErrors();
    updateExtraFieldVisibility();
    const hexMsg = (isFileUpload ? uploadedFileContent : messageBox.value)
        .trim()
        .toLowerCase();
    const key = $("hexKey").value.trim().toLowerCase();
    const mode = $("mode").value;

    // Input validations
    if (!hexMsg || !isHex(hexMsg)) {
        $("msgErr").textContent = "Valid hex required";
        return;
    }
    if (!isHex(key) || key.length !== 16) {
        $("keyErr").textContent = "Key must be 16-char hex";
        return;
    }

    const payload = { hex_message: hexMsg, hex_key: key, mode };

    // Check for required extra field
    if (mode !== "ECB") {
        const extra = extraField.value.trim();
        if (!isHex(extra)) {
            extraError.textContent =
                "IV / nonce / counter is required and must be hex.";
            return;
        }
        payload.extra = extra;
    }

    disableButtons(true);
    try {
        const res = await fetchDES("decrypt", payload);

        // Show decrypted text
        writeResult(
            `Decrypted (utf-8):\n${res.decrypted_text}\n\nHex:\n${res.decrypted_hex}`
        );

        if (isFileUpload)
            downloadTextFile(res.decrypted_text, `decrypted_${Date.now()}.txt`);

        renderList("roundBox", "Round Results", res.round_results, "round");
        renderList("keyBox", "Key Expansions", res.key_expansions, "key");
    } catch (e) {
        writeResult(`Error: ${e.message}`);
        renderList("roundBox", "", [], "round");
        renderList("keyBox", "", [], "key");
    } finally {
        disableButtons(false);
    }
    $("viewDetailsBtn").style.display = "block";
}

// Download string content as a text file
function downloadTextFile(content, filename) {
    const blob = new Blob([content], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
}

// Get cookie by name
function getCookie(name) {
    return (
        document.cookie
            .split("; ")
            .find((r) => r.startsWith(name + "="))
            ?.split("=")[1] || null
    );
}

// Initialize auth (update header links based on login status)
(function initAuth() {
    const token = getCookie("token");
    const box = $("authLinks");
    if (!token) {
        box.innerHTML = `<a class="btn" href="/login">Login</a><a class="btn" href="/register">Register</a>`;
        return;
    }
    try {
        const p = JSON.parse(atob(token.split(".")[1] || "{}"));
        const uid = p.user_id;
        const pic = `/avatar/${uid}`;
        box.innerHTML = `<a class="btn" href="/history">View History</a><a href="/profile"><img src="${pic}" class="avatar-thumb" alt="profile"></a>`;
    } catch {
        box.textContent = "";
    }
})();

// Generate random 16-character hex key
function generateRandomKey() {
    const hex = "0123456789abcdef";
    let k = "";
    for (let i = 0; i < 16; i++) k += hex[Math.floor(Math.random() * hex.length)];
    $("hexKey").value = k;
}
keyIconBtn.addEventListener("click", generateRandomKey);
