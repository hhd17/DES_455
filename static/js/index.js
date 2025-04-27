let isFileUpload = false;
let uploadedFileContent = "";

const $ = (id) => document.getElementById(id);

const messageBox = $("message");
const uploadIconBtn = $("uploadIcon");
const clearIconBtn = $("clearIcon");
const keyIconBtn = $("keyIcon");
const pasteIconBtn = $("pasteIcon");
const extraField = $("extraParam");
const extraLabel = $("extraLabel");
const extraError = $("extraErr");
const generatedExtraBox = $("generatedExtra");
const extraOutput = $("extraOutput");

const API = window.location.origin;

const isHex = (str) => /^[0-9a-fA-F]+$/.test(str);
const clearErrors = () => {
    $("msgErr").textContent = "";
    $("keyErr").textContent = "";
};

$("mode").addEventListener("change", updateExtraFieldVisibility);
$("operation").addEventListener("change", updateExtraFieldVisibility);
document.addEventListener("DOMContentLoaded", updateExtraFieldVisibility);

function updateExtraFieldVisibility() {
    const mode = $("mode").value;
    const op = $("operation").value;
    const show = op === "decrypt" && mode !== "ECB";
    extraField.style.display = extraLabel.style.display = show ? "block" : "none";
    extraField.disabled = !show;
    if (!show) {
        extraField.value = "";
        extraError.textContent = "";
    }
}

const fileInput = document.createElement("input");
fileInput.type = "file";
fileInput.accept = ".txt,.bin";
fileInput.style.display = "none";
document.body.appendChild(fileInput);

function showUploadIcon() {
    uploadIconBtn.style.display = "inline";
    clearIconBtn.style.display = "none";
    pasteIconBtn.style.display = "inline";
}
function showClearIcon() {
    uploadIconBtn.style.display = "none";
    clearIconBtn.style.display = "inline";
    pasteIconBtn.style.display = "none";
}

uploadIconBtn.addEventListener("click", () => fileInput.click());
messageBox.addEventListener("click", () => {
    if (isFileUpload) fileInput.click();
});

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
        showClearIcon();
    };
    reader.readAsArrayBuffer(file);
});

clearIconBtn.addEventListener("click", () => {
    isFileUpload = false;
    uploadedFileContent = "";
    messageBox.value = "";
    messageBox.readOnly = false;
    fileInput.value = "";
    messageBox.classList.remove("file-loaded");
    showUploadIcon();
});

messageBox.addEventListener("input", () => {
    if (isFileUpload) {
        isFileUpload = false;
        uploadedFileContent = "";
        messageBox.readOnly = false;
        messageBox.classList.remove("file-loaded");
        showUploadIcon();
    }
});

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
        }
    } catch { }
});

async function fetchDES(endpoint, payload) {
    const r = await fetch(`${API}/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        credentials: "include",
    });
    return r.json();
}

const writeResult = (txt) => ($("result").textContent = txt);

const renderList = (id, title, items, className) => {
    const box = $(id);
    box.innerHTML = items.length ? `<h4>${title}</h4>` : "";
    items.forEach((item, i) => {
        let displayValue = item;
 
        // Special handling for first round which is an object
        if (i === 0 && typeof item === "object" && item !== null) {
            // Use the "Combined (pre-swap)" value or any appropriate value
            displayValue = item["Combined (pre-swap)"] || JSON.stringify(item);
            // If the value is binary, convert to hex for display consistency
            if (displayValue && displayValue.match(/^[01]+$/)) {
                displayValue = parseInt(displayValue, 2).toString(16).toUpperCase();
            }
        }

        box.innerHTML += `<div class="${className}">Round ${i + 1}: ${displayValue}</div>`;
    })
};

function handleSubmit() {
    $("operation").value === "encrypt" ? handleEncrypt() : handleDecrypt();
}
const disableButtons = (s) => ($("submitBtn").disabled = s);

async function handleEncrypt() {
    clearErrors();
    updateExtraFieldVisibility();
    const message = isFileUpload ? uploadedFileContent : messageBox.value.trim();
    const key = $("hexKey").value.trim().toLowerCase();
    const mode = $("mode").value;
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
        writeResult(`Encrypted (hex):\n${res.encrypted_hex}`);
        if (isFileUpload)
            downloadTextFile(res.encrypted_hex, `encrypted_${Date.now()}.txt`);
        if (res.extra) {
            generatedExtraBox.style.display = "block";
            extraOutput.textContent = res.extra;
        } else {
            generatedExtraBox.style.display = "none";
            extraOutput.textContent = "";
        }
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

async function handleDecrypt() {
    clearErrors();
    updateExtraFieldVisibility();
    const hexMsg = (isFileUpload ? uploadedFileContent : messageBox.value)
        .trim()
        .toLowerCase();
    const key = $("hexKey").value.trim().toLowerCase();
    const mode = $("mode").value;
    if (!hexMsg || !isHex(hexMsg)) {
        $("msgErr").textContent = "Valid hex required";
        return;
    }
    if (!isHex(key) || key.length !== 16) {
        $("keyErr").textContent = "Key must be 16-char hex";
        return;
    }
    const payload = { hex_message: hexMsg, hex_key: key, mode };
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

function downloadTextFile(content, filename) {
    const blob = new Blob([content], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
}

function getCookie(name) {
    return (
        document.cookie
            .split("; ")
            .find((r) => r.startsWith(name + "="))
            ?.split("=")[1] || null
    );
}

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

function generateRandomKey() {
    const hex = "0123456789abcdef";
    let k = "";
    for (let i = 0; i < 16; i++) k += hex[Math.floor(Math.random() * hex.length)];
    $("hexKey").value = k;
}
keyIconBtn.addEventListener("click", generateRandomKey);
