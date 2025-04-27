let isFileUpload = false;
const $ = (id) => document.getElementById(id);
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
$("mode").addEventListener("change", () => {
    updateExtraFieldVisibility();
});
$("operation").addEventListener("change", updateExtraFieldVisibility);
const disableButtons = (disabled) => {
    $("submitBtn").disabled = disabled;
};
$("message").addEventListener("input", () => {
    isFileUpload = false;
});
document.addEventListener("DOMContentLoaded", updateExtraFieldVisibility);

const writeResult = (text) => ($("result").textContent = text);

const renderList = (containerId, title, items, className) => {
    const box = $(containerId);
    box.innerHTML = items.length ? `<h4>${title}</h4>` : "";

    items.forEach((item, i) => {
        let displayValue = item;
        
        // Special handling for first round which is an object
        if (i === 0 && typeof item === 'object' && item !== null) {
            // Use the "Combined (pre-swap)" value or any appropriate value
            displayValue = item["Combined (pre-swap)"] || JSON.stringify(item);
            
            // If the value is binary, convert to hex for display consistency
            if (displayValue && displayValue.match(/^[01]+$/)) {
                displayValue = parseInt(displayValue, 2).toString(16).toUpperCase();
            }
        }
        
        box.innerHTML += `<div class="${className}">Round ${i + 1}: ${displayValue}</div>`;
    });
};

function updateExtraFieldVisibility() {
    const mode = $("mode").value;
    const operation = $("operation").value;

    const shouldShow = operation === "decrypt" && mode !== "ECB";

    // Toggle visibility
    extraField.style.display = shouldShow ? "block" : "none";
    extraLabel.style.display = shouldShow ? "block" : "none";

    // Optional: disable/enable field when shown
    extraField.disabled = !shouldShow;

    // Optional: reset field if not needed
    if (!shouldShow) {
        extraField.value = "";
        extraError.textContent = "";
    }
}

async function fetchDES(endpoint, payload) {
    return fetch(`${API}/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        credentials: "include", // ✅  this line
    }).then((r) => r.json());
}

function handleSubmit() {
    const operation = document.getElementById("operation").value;
    if (operation === "encrypt") {
        handleEncrypt();
    } else {
        handleDecrypt();
    }
}

async function handleEncrypt() {
    clearErrors();
    updateExtraFieldVisibility();
    const message = $("message").value.trim();
    const key = $("hexKey").value.trim().toLowerCase();
    const mode = $("mode").value;

    if (!message) {
        $("msgErr").textContent = "Message required";
        return;
    }
    if (!isHex(key) || key.length !== 16) {
        $("keyErr").textContent = "Key must be 16‑char hex";
        return;
    }

    disableButtons(true);
    try {
        const result = await fetchDES("encrypt", {
            message,
            hex_key: key,
            mode,
        });
        writeResult(`Encrypted (hex):\n${result.encrypted_hex}`);
        if (isFileUpload) {
            downloadTextFile(result.encrypted_hex, `encrypted_${Date.now()}.txt`);
        }
        if (result.extra) {
            generatedExtraBox.style.display = "block";
            extraOutput.textContent = result.extra;
        } else {
            generatedExtraBox.style.display = "none";
            extraOutput.textContent = "";
        }
        renderList("roundBox", "Round Results", result.round_results, "round");
        renderList("keyBox", "Key Expansions", result.key_expansions, "key");
    } catch (e) {
        writeResult(`Error: ${e.message}`);
        renderList("roundBox", "", [], "round");
        renderList("keyBox", "", [], "key");
    } finally {
        disableButtons(false);
    }
    document.getElementById("viewDetailsBtn").style.display = "block";
}

async function handleDecrypt() {
    clearErrors();
    updateExtraFieldVisibility();
    const hexMsg = $("message").value.trim().toLowerCase();
    const key = $("hexKey").value.trim().toLowerCase();
    const mode = $("mode").value;
    const payload = { hex_message: hexMsg, hex_key: key, mode };
    if (!hexMsg || !isHex(hexMsg)) {
        $("msgErr").textContent = "Valid hex required";
        return;
    }
    if (!isHex(key) || key.length !== 16) {
        $("keyErr").textContent = "Key must be 16‑char hex";
        return;
    }
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
        const result = await fetchDES("decrypt", payload);
        writeResult(
            `Decrypted (utf‑8):\n${result.decrypted_text}\n\nHex:\n${result.decrypted_hex}`
        );
        if (isFileUpload) {
            downloadTextFile(result.decrypted_text, `decrypted_${Date.now()}.txt`);
        }
        renderList("roundBox", "Round Results", result.round_results, "round");
        renderList("keyBox", "Key Expansions", result.key_expansions, "key");
    } catch (e) {
        writeResult(`Error: ${e.message}`);
        renderList("roundBox", "", [], "round");
        renderList("keyBox", "", [], "key");
    } finally {
        disableButtons(false);
    }
    document.getElementById("viewDetailsBtn").style.display = "block";
}

const fileInput = document.createElement("input");
fileInput.type = "file";
fileInput.accept = ".txt,.bin";
fileInput.style.display = "none";
document.body.appendChild(fileInput);

// Add upload buttons dynamically

const uploadMessageBtn = $("uploadFileBtn");

uploadMessageBtn.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
        const mode = $("mode").value;
        const operation = $("operation").value;

        const result = new Uint8Array(reader.result);

        if (operation === "encrypt") {
            $("message").value = new TextDecoder().decode(result);
        } else {
            $("message").value = [...result].map(b => b.toString(16).padStart(2, "0")).join("");
        }

        isFileUpload = true; // ✅ Mark that the input came from file
    };
    reader.readAsArrayBuffer(file);
});

function downloadTextFile(content, filename) {
    const blob = new Blob([content], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
}


function getCookie(name) {
    return (
        document.cookie
            .split("; ")
            .find((row) => row.startsWith(name + "="))
            ?.split("=")[1] || null
    );
}

(function initAuth() {
    const token = getCookie("token");
    const box = $("authLinks");

    if (!token) {
        box.innerHTML = `
            <a class="btn" href="/login">Login</a>
            <a class="btn" href="/register">Register</a>
        `;
        return;
    }

    try {
        const payload = JSON.parse(atob(token.split(".")[1] || "{}"));
        const uid = payload.user_id;
        const pic = `/avatar/${uid}`;
        box.innerHTML = `
  <a class="btn" href="/history">View History</a>
  <a href="/profile">
      <img src="${pic}" class="avatar-thumb" alt="profile">
  </a>`;
    } catch {
        box.textContent = "";
    }
})();
